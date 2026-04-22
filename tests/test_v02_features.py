"""
Tests for Carapace v0.2 features:
  - Runtime Capability Enforcement
  - Card Expiry / TTL
  - Agent Card Versioning

Run: pytest tests/test_v02_features.py -v
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Any


# ── Minimal Card Stub ─────────────────────────────────────────────────────────
# Matches the shape of a real AgentCard without importing the SDK.

@dataclass
class MockOwner:
    public_key: str = "aabbccdd" * 8  # 64-char hex


@dataclass
class MockCard:
    id: str = "test-uuid-001"
    capabilities: list[dict] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    expires_at: str | None = None
    version: int = 1
    supersedes: str | None = None
    superseded_by: str | None = None
    owner: MockOwner = field(default_factory=MockOwner)
    status: str = "active"
    created_at: str | None = None


def make_card(
    caps: list[str] | None = None,
    expires_at: str | None = None,
    card_id: str = "test-uuid-001",
    version: int = 1,
    supersedes: str | None = None,
    owner_key: str | None = None,
) -> MockCard:
    capabilities = [
        {"id": c, "name": c, "description": f"Cap: {c}"}
        for c in (caps or [])
    ]
    owner = MockOwner(public_key=owner_key or ("aabbccdd" * 8))
    return MockCard(
        id=card_id,
        capabilities=capabilities,
        expires_at=expires_at,
        version=version,
        supersedes=supersedes,
        owner=owner,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ENFORCEMENT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

from carapace.enforce import (
    enforce,
    enforce_all,
    enforce_any,
    has_capability,
    require_capability,
    CapabilityDenied,
    CardExpired,
    EnforcementPolicy,
)


class TestHasCapability:
    def test_exact_match(self):
        card = make_card(["carapace:read:email"])
        assert has_capability(card, "carapace:read:email") is True

    def test_no_match(self):
        card = make_card(["carapace:read:email"])
        assert has_capability(card, "carapace:write:email") is False

    def test_empty_capabilities(self):
        card = make_card([])
        assert has_capability(card, "carapace:read:email") is False

    def test_wildcard_in_required(self):
        card = make_card(["carapace:read:email", "carapace:read:calendar"])
        assert has_capability(card, "carapace:read:*") is True

    def test_wildcard_in_required_no_match(self):
        card = make_card(["carapace:write:email"])
        assert has_capability(card, "carapace:read:*") is False

    def test_wildcard_in_declared(self):
        card = make_card(["carapace:read:*"])
        assert has_capability(card, "carapace:read:email") is True
        assert has_capability(card, "carapace:read:database") is True

    def test_wildcard_in_declared_no_match(self):
        card = make_card(["carapace:read:*"])
        assert has_capability(card, "carapace:write:email") is False

    def test_legacy_capability_ids(self):
        """v0.1.1 cards may have non-namespaced capability IDs."""
        card = make_card(["research", "summarize"])
        assert has_capability(card, "research") is True
        assert has_capability(card, "carapace:read:research") is False


class TestEnforce:
    def test_passes_when_capable(self):
        card = make_card(["carapace:write:database"])
        enforce(card, "carapace:write:database")  # Should not raise

    def test_raises_when_not_capable(self):
        card = make_card(["carapace:read:email"])
        with pytest.raises(CapabilityDenied) as exc_info:
            enforce(card, "carapace:write:database")
        assert "carapace:write:database" in str(exc_info.value)

    def test_raises_on_expired_card(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        card = make_card(["carapace:read:email"], expires_at=yesterday)
        with pytest.raises(CardExpired):
            enforce(card, "carapace:read:email")

    def test_skip_expiry_check(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        card = make_card(["carapace:read:email"], expires_at=yesterday)
        # Should not raise — expiry check disabled
        enforce(card, "carapace:read:email", check_expiry=False)

    def test_no_expiry_passes(self):
        card = make_card(["carapace:read:email"])  # No expires_at
        enforce(card, "carapace:read:email")  # Should not raise


class TestEnforceAll:
    def test_all_present(self):
        card = make_card(["carapace:read:email", "carapace:write:email"])
        enforce_all(card, ["carapace:read:email", "carapace:write:email"])

    def test_one_missing(self):
        card = make_card(["carapace:read:email"])
        with pytest.raises(CapabilityDenied):
            enforce_all(card, ["carapace:read:email", "carapace:write:email"])


class TestEnforceAny:
    def test_one_present(self):
        card = make_card(["carapace:read:email"])
        enforce_any(card, ["carapace:read:email", "carapace:write:email"])

    def test_none_present(self):
        card = make_card(["carapace:delete:email"])
        with pytest.raises(CapabilityDenied):
            enforce_any(card, ["carapace:read:email", "carapace:write:email"])


class TestRequireCapabilityDecorator:
    def test_decorator_passes(self):
        card = make_card(["carapace:write:database"])

        @require_capability("carapace:write:database")
        def write_record(card, data):
            return f"wrote {data}"

        assert write_record(card, "test") == "wrote test"

    def test_decorator_blocks(self):
        card = make_card(["carapace:read:email"])

        @require_capability("carapace:write:database")
        def write_record(card, data):
            return f"wrote {data}"

        with pytest.raises(CapabilityDenied):
            write_record(card, "test")


class TestEnforcementPolicy:
    def test_policy_enforcement(self):
        policy = EnforcementPolicy(
            name="email-service",
            rules={
                "read_inbox": ["carapace:read:email"],
                "send_email": ["carapace:write:email"],
                "delete_email": ["carapace:delete:email"],
            },
        )
        card = make_card(["carapace:read:email", "carapace:write:email"])

        policy.enforce(card, "read_inbox")  # OK
        policy.enforce(card, "send_email")  # OK
        with pytest.raises(CapabilityDenied):
            policy.enforce(card, "delete_email")

    def test_policy_unknown_action(self):
        policy = EnforcementPolicy(name="test", rules={"do_thing": ["cap:a"]})
        card = make_card(["cap:a"])
        with pytest.raises(ValueError, match="Unknown action"):
            policy.enforce(card, "nonexistent_action")

    def test_policy_audit(self):
        policy = EnforcementPolicy(
            name="test",
            rules={
                "read": ["carapace:read:email"],
                "write": ["carapace:write:email"],
            },
        )
        card = make_card(["carapace:read:email"])
        audit = policy.audit_card(card)
        assert audit == {"read": True, "write": False}


# ═══════════════════════════════════════════════════════════════════════════════
# EXPIRY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

from carapace.expiry import (
    make_expires_at,
    parse_expires_at,
    check_expiry,
    is_expired,
    time_remaining,
    validate_expiry_for_verify,
    ExpiryStatus,
)


class TestMakeExpiresAt:
    def test_ttl_hours(self):
        result = make_expires_at(ttl_hours=24)
        assert result is not None
        parsed = parse_expires_at(result)
        assert parsed is not None
        # Should be ~24h from now
        diff = parsed - datetime.now(timezone.utc)
        assert 23.9 < diff.total_seconds() / 3600 < 24.1

    def test_ttl_days(self):
        result = make_expires_at(ttl_days=90)
        assert result is not None
        parsed = parse_expires_at(result)
        diff = parsed - datetime.now(timezone.utc)
        assert 89.9 < diff.total_seconds() / 86400 < 90.1

    def test_absolute_string(self):
        result = make_expires_at(absolute="2026-12-31T23:59:59Z")
        assert result == "2026-12-31T23:59:59Z"

    def test_absolute_datetime(self):
        dt = datetime(2026, 12, 31, tzinfo=timezone.utc)
        result = make_expires_at(absolute=dt)
        assert "2026-12-31" in result

    def test_no_args_returns_none(self):
        assert make_expires_at() is None

    def test_negative_ttl_raises(self):
        with pytest.raises(ValueError, match="positive"):
            make_expires_at(ttl_hours=-1)


class TestCheckExpiry:
    def test_no_expiry(self):
        card = make_card([])
        assert check_expiry(card) == ExpiryStatus.NO_EXPIRY

    def test_valid(self):
        in_2_days = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        card = make_card([], expires_at=in_2_days)
        assert check_expiry(card) == ExpiryStatus.VALID

    def test_expired(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        card = make_card([], expires_at=yesterday)
        assert check_expiry(card) == ExpiryStatus.EXPIRED

    def test_expiring_soon(self):
        in_12h = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
        card = make_card([], expires_at=in_12h)
        assert check_expiry(card, warning_threshold=timedelta(hours=24)) == ExpiryStatus.EXPIRING_SOON

    def test_dict_card(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        card = {"expires_at": yesterday}
        assert check_expiry(card) == ExpiryStatus.EXPIRED

    def test_override_now(self):
        fixed_expiry = "2026-06-01T00:00:00Z"
        card = make_card([], expires_at=fixed_expiry)
        before = datetime(2026, 5, 15, tzinfo=timezone.utc)
        after = datetime(2026, 7, 1, tzinfo=timezone.utc)
        assert check_expiry(card, now=before) == ExpiryStatus.VALID
        assert check_expiry(card, now=after) == ExpiryStatus.EXPIRED


class TestIsExpired:
    def test_not_expired(self):
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        card = make_card([], expires_at=tomorrow)
        assert is_expired(card) is False

    def test_expired(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        card = make_card([], expires_at=yesterday)
        assert is_expired(card) is True


class TestTimeRemaining:
    def test_no_expiry(self):
        card = make_card([])
        assert time_remaining(card) is None

    def test_positive(self):
        in_2_days = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        card = make_card([], expires_at=in_2_days)
        remaining = time_remaining(card)
        assert remaining is not None
        assert remaining.total_seconds() > 0

    def test_negative_when_expired(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        card = make_card([], expires_at=yesterday)
        remaining = time_remaining(card)
        assert remaining is not None
        assert remaining.total_seconds() < 0


class TestValidateExpiryForVerify:
    def test_expired_card(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        card = make_card([], expires_at=yesterday)
        result = validate_expiry_for_verify(card)
        assert result["passed"] is False
        assert result["reason"] == "card_expired"

    def test_valid_card(self):
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        card = make_card([], expires_at=tomorrow)
        result = validate_expiry_for_verify(card)
        assert result["passed"] is True

    def test_expiring_soon(self):
        in_6h = (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat()
        card = make_card([], expires_at=in_6h)
        result = validate_expiry_for_verify(card)
        assert result["passed"] is True
        assert result["status"] == "expiring_soon"
        assert result["hours_remaining"] is not None


# ═══════════════════════════════════════════════════════════════════════════════
# VERSIONING TESTS
# ═══════════════════════════════════════════════════════════════════════════════

from carapace.versioning import (
    VersionEntry,
    VersionChain,
    validate_version_chain,
    prepare_version_fields,
    validate_supersedes_registration,
    VersionChainError,
    OwnerMismatchError,
    VersionSequenceError,
    SupersedesNotFoundError,
)


class TestPrepareVersionFields:
    def test_first_registration(self):
        fields = prepare_version_fields()
        assert fields == {"version": 1, "supersedes": None}

    def test_update_registration(self):
        old_card = make_card([], card_id="old-uuid", version=1)
        fields = prepare_version_fields(supersedes_card=old_card)
        assert fields == {"version": 2, "supersedes": "old-uuid"}

    def test_update_from_dict(self):
        old_card = {"id": "old-uuid", "version": 3}
        fields = prepare_version_fields(supersedes_card=old_card)
        assert fields == {"version": 4, "supersedes": "old-uuid"}


class TestValidateSupersedesRegistration:
    def test_matching_owner(self):
        key = "aa" * 32
        old_card = make_card([], owner_key=key)
        # Should not raise
        validate_supersedes_registration(key, old_card)

    def test_mismatched_owner(self):
        old_card = make_card([], owner_key="aa" * 32)
        with pytest.raises(OwnerMismatchError):
            validate_supersedes_registration("bb" * 32, old_card)


class TestVersionChainValidation:
    def test_single_card(self):
        card = make_card([], card_id="v1", version=1)
        chain = validate_version_chain([card])
        assert chain.length == 1
        assert chain.current.card_id == "v1"

    def test_two_card_chain(self):
        key = "cc" * 32
        v1 = make_card([], card_id="v1", version=1, owner_key=key)
        v2 = make_card([], card_id="v2", version=2, supersedes="v1", owner_key=key)
        chain = validate_version_chain([v2, v1])  # Deliberately out of order
        assert chain.length == 2
        assert chain.original.card_id == "v1"
        assert chain.current.card_id == "v2"
        assert chain.is_valid()

    def test_three_card_chain(self):
        key = "dd" * 32
        v1 = make_card([], card_id="v1", version=1, owner_key=key)
        v2 = make_card([], card_id="v2", version=2, supersedes="v1", owner_key=key)
        v3 = make_card([], card_id="v3", version=3, supersedes="v2", owner_key=key)
        chain = validate_version_chain([v3, v1, v2])
        assert chain.length == 3
        assert chain.is_valid()

    def test_multiple_owners_fails(self):
        v1 = make_card([], card_id="v1", version=1, owner_key="aa" * 32)
        v2 = make_card([], card_id="v2", version=2, supersedes="v1", owner_key="bb" * 32)
        with pytest.raises(OwnerMismatchError):
            validate_version_chain([v1, v2])

    def test_duplicate_versions_fails(self):
        key = "ee" * 32
        v1 = make_card([], card_id="v1a", version=1, owner_key=key)
        v1b = make_card([], card_id="v1b", version=1, owner_key=key)
        with pytest.raises(VersionSequenceError):
            validate_version_chain([v1, v1b])

    def test_multiple_originals_fails(self):
        key = "ff" * 32
        v1 = make_card([], card_id="v1", version=1, owner_key=key)
        v2 = make_card([], card_id="v2", version=2, owner_key=key)  # No supersedes!
        with pytest.raises(VersionChainError, match="exactly one original"):
            validate_version_chain([v1, v2])

    def test_broken_supersedes_fails(self):
        key = "00" * 32
        v1 = make_card([], card_id="v1", version=1, owner_key=key)
        v2 = make_card([], card_id="v2", version=2, supersedes="nonexistent", owner_key=key)
        with pytest.raises(SupersedesNotFoundError):
            validate_version_chain([v1, v2])

    def test_empty_chain(self):
        chain = validate_version_chain([])
        assert chain.length == 0
        assert chain.current is None

    def test_dict_cards(self):
        key = "11" * 32
        v1 = {"id": "v1", "version": 1, "supersedes": None, "owner": {"public_key": key}}
        v2 = {"id": "v2", "version": 2, "supersedes": "v1", "owner": {"public_key": key}}
        chain = validate_version_chain([v1, v2])
        assert chain.length == 2
        assert chain.is_valid()
