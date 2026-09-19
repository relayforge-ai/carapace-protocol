"""Adversarial regressions for REL-692; all keys and actions are synthetic."""
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carapace.enforce import CardExpired, enforce, enforce_all, enforce_any
from carapace.receipt import create_receipt, verify_receipt, post_receipt, post_receipt_async
from carapace.receipt_protocol import content_hash


def vector():
    return json.loads((Path(__file__).resolve().parents[1] / 'test-vectors/receipt-v2.json').read_text(encoding='utf-8'))


def test_shared_signed_vector_and_json_canonicalization():
    data = vector()
    assert content_hash(data['args']) == data['receipt']['args_hash']
    assert verify_receipt(data['receipt'], data['receipt']['public_key'])


@pytest.mark.parametrize('field,value', [
    ('tool_id', 'fixture.delete'), ('agent_id', 'another-agent'), ('status', 'error'),
    ('args_hash', '0'*64), ('result_hash', '1'*64), ('receipt_id', 'different'),
    ('issued_at', '2026-01-02T00:00:00Z'), ('domain', 'other.protocol'),
    ('receipt_version', '1'), ('tool_version', '2'), ('authorization_id', 'other-permit'),
    ('public_key', '2'*64), ('call_hash', '3'*64), ('signature', '4'*128),
])
def test_every_signed_field_is_bound(field, value):
    receipt = vector()['receipt']
    receipt[field] = value
    assert not verify_receipt(receipt)


def test_unknown_and_missing_fields_fail():
    receipt = vector()['receipt']
    receipt['unbound_claim'] = 'approved'
    assert not verify_receipt(receipt)
    receipt.pop('unbound_claim')
    receipt.pop('tool_version')
    assert not verify_receipt(receipt)


def test_legacy_signature_is_not_promoted_to_verified():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    receipt = {'call_hash': 'a'*64, 'signature': key.sign(b'a'*64).hex(),
               'public_key': key.public_key().public_bytes_raw().hex()}
    assert not verify_receipt(receipt)


@pytest.mark.parametrize('value', [float('nan'), float('inf'), 2**53, object(), {'x': '\ud800'}, {1: 'bad'}])
def test_ambiguous_json_is_rejected(value):
    with pytest.raises((ValueError, TypeError, UnicodeError)):
        create_receipt('fixture.read', value)


@pytest.mark.parametrize('expiry', ['2000-01-01T00:00:00Z', '', 'nonsense', 0, False, '2099-01-01T00:00:00'])
@pytest.mark.parametrize('representation', [dict, lambda **kw: SimpleNamespace(**kw)])
@pytest.mark.parametrize('guard', [lambda c: enforce(c, 'read'), lambda c: enforce_all(c, ['read']), lambda c: enforce_any(c, ['read'])])
def test_expired_and_invalid_cards_are_rejected(expiry, representation, guard):
    with pytest.raises(CardExpired):
        guard(representation(id='fixture', capabilities=['read'], expires_at=expiry))


def test_boundary_future_and_absent_expiry(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 1, 1, tzinfo=timezone.utc)
    module = importlib.import_module('carapace.enforce')
    monkeypatch.setattr(module, 'datetime', Clock)
    with pytest.raises(CardExpired):
        enforce({'capabilities': ['read'], 'expires_at': '2025-12-31T16:00:00-08:00'}, 'read')
    enforce({'capabilities': ['read'], 'expires_at': '2026-01-01T00:00:01Z'}, 'read')
    enforce({'capabilities': ['read']}, 'read')
    enforce({'capabilities': ['read'], 'expires_at': 'bad'}, 'read', check_expiry=False)


@pytest.mark.parametrize('ack,expected', [
    ({'ok': True}, False),
    ({'ok': True, 'verification_status': 'legacy_unverified'}, False),
    ({'ok': True, 'verification_status': 'verified_v2'}, True),
])
def test_upload_requires_v2_acknowledgement(ack, expected):
    response = MagicMock(status_code=200)
    response.json.return_value = ack
    with patch('httpx.post', return_value=response):
        assert post_receipt('https://example.com', vector()['receipt']) is expected


@pytest.mark.asyncio
async def test_async_upload_detects_old_server():
    response = MagicMock(status_code=200)
    response.json.return_value = {'ok': True}
    with patch('httpx.AsyncClient') as factory:
        factory.return_value.__aenter__.return_value.post = AsyncMock(return_value=response)
        assert not await post_receipt_async('https://example.com', vector()['receipt'])
