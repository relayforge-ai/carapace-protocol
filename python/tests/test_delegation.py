"""
Tests for Carapace v0.3 — Delegation Chains

Run: pytest tests/test_delegation.py -v
"""

import pytest
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Any

from carapace.delegation import (
    DelegationToken,
    DelegationVerifyResult,
    create_delegation,
    verify_delegation,
    verify_delegation_chain,
    enforce_delegated,
    redelegate,
    validate_capability_subset,
    narrow_capabilities,
    CapabilityEscalation,
    DelegationExpired,
    DelegationChainBroken,
    RedelegationDepthExceeded,
    DelegatorCardInvalid,
    TTLExceedsDelegator,
    DEFAULT_REDELEGATION_DEPTH,
)


# ── Test Fixtures ─────────────────────────────────────────────────────────────

@dataclass
class MockOwner:
    public_key: str = "aa" * 32


@dataclass
class MockCard:
    id: str = "agent-a-uuid"
    capabilities: list[dict] = field(default_factory=list)
    expires_at: str | None = None
    owner: MockOwner = field(default_factory=MockOwner)
    status: str = "active"


def make_card(
    card_id: str = "agent-a-uuid",
    caps: list[str] | None = None,
    expires_at: str | None = None,
    owner_key: str | None = None,
    status: str = "active",
) -> MockCard:
    capabilities = [
        {"id": c, "name": c, "description": f"Cap: {c}"}
        for c in (caps or [])
    ]
    return MockCard(
        id=card_id,
        capabilities=capabilities,
        expires_at=expires_at,
        owner=MockOwner(public_key=owner_key or ("aa" * 32)),
        status=status,
    )


def future(hours: float = 24) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def past(hours: float = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


# ═══════════════════════════════════════════════════════════════════════════════
# CAPABILITY SUBSET VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestCapabilitySubset:
    def test_exact_subset(self):
        validate_capability_subset(
            ["carapace:read:email"],
            ["carapace:read:email", "carapace:write:email"],
        )  # Should not raise

    def test_exact_match(self):
        validate_capability_subset(
            ["carapace:read:email"],
            ["carapace:read:email"],
        )

    def test_escalation_raises(self):
        with pytest.raises(CapabilityEscalation):
            validate_capability_subset(
                ["carapace:read:email", "carapace:delete:email"],
                ["carapace:read:email"],
            )

    def test_wildcard_covers_specific(self):
        validate_capability_subset(
            ["carapace:read:email"],
            ["carapace:read:*"],
        )

    def test_specific_doesnt_cover_wildcard(self):
        with pytest.raises(CapabilityEscalation):
            validate_capability_subset(
                ["carapace:read:*"],
                ["carapace:read:email"],
            )

    def test_wildcard_narrowing(self):
        """carapace:read:* is a valid subset of carapace:*"""
        # This is a narrowing of a broader wildcard — it should be allowed
        # only if the parent has the broader wildcard
        validate_capability_subset(
            ["carapace:read:*"],
            ["carapace:*"],
        )

    def test_empty_request_passes(self):
        validate_capability_subset([], ["carapace:read:email"])

    def test_empty_available_fails(self):
        with pytest.raises(CapabilityEscalation):
            validate_capability_subset(["carapace:read:email"], [])


# ═══════════════════════════════════════════════════════════════════════════════
# TOKEN CREATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateDelegation:
    def test_basic_creation(self):
        card = make_card(caps=["carapace:read:email", "carapace:write:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        assert token.delegator_card_id == "agent-a-uuid"
        assert token.delegate_card_id == "agent-b-uuid"
        assert token.delegated_capabilities == ["carapace:read:email"]
        assert token.is_root is True
        assert token.can_redelegate is True
        assert token.parent_delegation_id is None
        assert len(token.nonce) == 32  # 16 bytes hex

    def test_capability_escalation_blocked(self):
        card = make_card(caps=["carapace:read:email"])
        with pytest.raises(CapabilityEscalation):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b-uuid",
                capabilities=["carapace:write:database"],
                ttl_hours=4,
            )

    def test_expired_delegator_blocked(self):
        card = make_card(caps=["carapace:read:email"], expires_at=past(1))
        with pytest.raises(DelegatorCardInvalid):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b-uuid",
                capabilities=["carapace:read:email"],
                ttl_hours=4,
            )

    def test_revoked_delegator_blocked(self):
        card = make_card(caps=["carapace:read:email"], status="revoked")
        with pytest.raises(DelegatorCardInvalid):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b-uuid",
                capabilities=["carapace:read:email"],
                ttl_hours=4,
            )

    def test_ttl_exceeds_delegator_blocked(self):
        card = make_card(
            caps=["carapace:read:email"],
            expires_at=future(2),  # Card expires in 2 hours
        )
        with pytest.raises(TTLExceedsDelegator):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b-uuid",
                capabilities=["carapace:read:email"],
                ttl_hours=24,  # 24 hours > 2 hours
            )

    def test_ttl_within_delegator(self):
        card = make_card(
            caps=["carapace:read:email"],
            expires_at=future(48),
        )
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        assert token.expires_at is not None

    def test_default_ttl_when_no_card_expiry(self):
        card = make_card(caps=["carapace:read:email"])  # No expires_at
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
        )
        # Should default to DEFAULT_MAX_TTL_HOURS
        assert token.expires_at is not None

    def test_custom_redelegation_depth(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
            max_redelegation_depth=0,  # Terminal — cannot re-delegate
        )
        assert token.max_redelegation_depth == 0
        assert token.can_redelegate is False

    def test_task_context(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
            task_context="Process Q2 invoices from inbox",
        )
        assert token.task_context == "Process Q2 invoices from inbox"

    def test_wildcard_delegation(self):
        card = make_card(caps=["carapace:read:*", "carapace:write:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],  # Narrowed from read:*
            ttl_hours=4,
        )
        assert "carapace:read:email" in token.delegated_capabilities

    def test_dict_card(self):
        card = {
            "id": "agent-a-uuid",
            "capabilities": [{"id": "carapace:read:email", "name": "r", "description": "d"}],
            "owner": {"public_key": "aa" * 32},
            "expires_at": None,
        }
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        assert token.delegator_card_id == "agent-a-uuid"


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLE TOKEN VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyDelegation:
    def test_valid_token(self):
        card = make_card(caps=["carapace:read:email", "carapace:write:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        result = verify_delegation(token, card)
        assert result.valid is True
        assert result.capabilities == ["carapace:read:email"]

    def test_expired_token(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # Force expiry
        token.expires_at = past(1)
        result = verify_delegation(token, card)
        assert result.valid is False
        assert result.reason == "delegation_expired"

    def test_expired_delegator_card(self):
        card = make_card(
            caps=["carapace:read:email"],
            expires_at=future(48),
        )
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # Expire the card after token creation
        card.expires_at = past(1)
        result = verify_delegation(token, card)
        assert result.valid is False
        assert result.reason == "delegator_card_expired"

    def test_revoked_delegator_card(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        card.status = "revoked"
        result = verify_delegation(token, card)
        assert result.valid is False
        assert "revoked" in result.reason

    def test_card_id_mismatch(self):
        card_a = make_card(card_id="agent-a", caps=["carapace:read:email"])
        card_b = make_card(card_id="agent-b", caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        result = verify_delegation(token, card_b)  # Wrong card
        assert result.valid is False
        assert result.reason == "delegator_card_id_mismatch"

    def test_token_from_dict(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b-uuid",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        token_dict = {**token.to_dict(), "signature": token.signature}
        result = verify_delegation(token_dict, card)
        assert result.valid is True


# ═══════════════════════════════════════════════════════════════════════════════
# RE-DELEGATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestRedelegation:
    def test_basic_redelegation(self):
        card_a = make_card(
            card_id="agent-a",
            caps=["carapace:read:email", "carapace:write:email", "carapace:delete:email"],
        )
        card_b = make_card(card_id="agent-b", caps=["carapace:read:email"])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email", "carapace:write:email"],
            ttl_hours=8,
            max_redelegation_depth=2,
        )

        token_bc = redelegate(
            parent_token=token_ab,
            redelegator_card=card_b,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],  # Narrowed further
            ttl_hours=4,
        )

        assert token_bc.parent_delegation_id == token_ab.id
        assert token_bc.max_redelegation_depth == 1  # Decremented
        assert token_bc.delegated_capabilities == ["carapace:read:email"]
        assert token_bc.is_root is False

    def test_redelegation_depth_zero_blocks(self):
        card_a = make_card(card_id="agent-a", caps=["carapace:read:email"])
        card_b = make_card(card_id="agent-b", caps=["carapace:read:email"])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=8,
            max_redelegation_depth=0,  # Terminal
        )

        with pytest.raises(RedelegationDepthExceeded):
            redelegate(
                parent_token=token_ab,
                redelegator_card=card_b,
                delegate_card_id="agent-c",
                capabilities=["carapace:read:email"],
                ttl_hours=4,
            )

    def test_redelegation_capability_escalation_blocked(self):
        card_a = make_card(
            card_id="agent-a",
            caps=["carapace:read:email", "carapace:write:email"],
        )
        card_b = make_card(card_id="agent-b", caps=["carapace:read:email"])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],  # Only read
            ttl_hours=8,
        )

        # B tries to delegate write (which B doesn't have via token_ab)
        with pytest.raises(CapabilityEscalation):
            redelegate(
                parent_token=token_ab,
                redelegator_card=card_b,
                delegate_card_id="agent-c",
                capabilities=["carapace:write:email"],
                ttl_hours=4,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# CHAIN VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestChainVerification:
    def test_single_token_chain(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        result = verify_delegation_chain([token], card)
        assert result.valid is True
        assert result.chain_depth == 1

    def test_two_link_chain(self):
        card_a = make_card(
            card_id="agent-a",
            caps=["carapace:read:email", "carapace:write:email"],
        )
        card_b = make_card(card_id="agent-b", caps=["carapace:read:email"])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email", "carapace:write:email"],
            ttl_hours=8,
            max_redelegation_depth=2,
        )

        token_bc = redelegate(
            parent_token=token_ab,
            redelegator_card=card_b,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )

        result = verify_delegation_chain([token_ab, token_bc], card_a)
        assert result.valid is True
        assert result.chain_depth == 2
        assert result.capabilities == ["carapace:read:email"]
        assert result.delegate_card_id == "agent-c"

    def test_three_link_chain(self):
        card_a = make_card(
            card_id="agent-a",
            caps=["carapace:read:email", "carapace:write:email", "carapace:execute:workflow"],
        )
        card_b = make_card(card_id="agent-b", caps=[])
        card_c = make_card(card_id="agent-c", caps=[])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email", "carapace:write:email"],
            ttl_hours=8,
            max_redelegation_depth=3,
        )
        token_bc = redelegate(
            parent_token=token_ab,
            redelegator_card=card_b,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],
            ttl_hours=6,
        )
        token_cd = redelegate(
            parent_token=token_bc,
            redelegator_card=card_c,
            delegate_card_id="agent-d",
            capabilities=["carapace:read:email"],
            ttl_hours=2,
        )

        result = verify_delegation_chain([token_ab, token_bc, token_cd], card_a)
        assert result.valid is True
        assert result.chain_depth == 3
        assert result.delegate_card_id == "agent-d"

    def test_broken_parent_reference(self):
        card_a = make_card(card_id="agent-a", caps=["carapace:read:email"])
        card_b = make_card(card_id="agent-b", caps=[])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=8,
            max_redelegation_depth=2,
        )
        token_bc = redelegate(
            parent_token=token_ab,
            redelegator_card=card_b,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # Corrupt the parent reference
        token_bc.parent_delegation_id = "wrong-id"

        result = verify_delegation_chain([token_ab, token_bc], card_a)
        assert result.valid is False
        assert "parent_delegation_id mismatch" in result.reason

    def test_chain_discontinuity(self):
        card_a = make_card(card_id="agent-a", caps=["carapace:read:email"])
        card_x = make_card(card_id="agent-x", caps=["carapace:read:email"])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=8,
            max_redelegation_depth=2,
        )
        # Create a token from X (not B) — chain breaks
        token_xc = create_delegation(
            delegator_card=card_x,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        token_xc.parent_delegation_id = token_ab.id  # Fake parent ref

        result = verify_delegation_chain([token_ab, token_xc], card_a)
        assert result.valid is False
        assert "chain discontinuity" in result.reason

    def test_capability_escalation_in_chain(self):
        card_a = make_card(
            card_id="agent-a",
            caps=["carapace:read:email", "carapace:write:email"],
        )
        card_b = make_card(card_id="agent-b", caps=[])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],  # Only read
            ttl_hours=8,
            max_redelegation_depth=2,
        )
        # Manually create a fraudulent token claiming write
        token_bc = DelegationToken(
            id="fake-token",
            delegator_card_id="agent-b",
            delegator_public_key="bb" * 32,
            delegate_card_id="agent-c",
            delegated_capabilities=["carapace:read:email", "carapace:write:email"],  # Escalated!
            expires_at=future(4),
            created_at=datetime.now(timezone.utc).isoformat(),
            parent_delegation_id=token_ab.id,
            max_redelegation_depth=1,
            nonce="fake",
        )

        result = verify_delegation_chain([token_ab, token_bc], card_a)
        assert result.valid is False
        assert "capability_escalation" in result.reason

    def test_ttl_escalation_in_chain(self):
        card_a = make_card(card_id="agent-a", caps=["carapace:read:email"])
        card_b = make_card(card_id="agent-b", caps=[])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
            max_redelegation_depth=2,
        )
        # Manually create a token with longer TTL than parent
        token_bc = DelegationToken(
            id="ttl-fraud",
            delegator_card_id="agent-b",
            delegator_public_key="bb" * 32,
            delegate_card_id="agent-c",
            delegated_capabilities=["carapace:read:email"],
            expires_at=future(48),  # Way beyond parent's 4h
            created_at=datetime.now(timezone.utc).isoformat(),
            parent_delegation_id=token_ab.id,
            max_redelegation_depth=1,
            nonce="fake",
        )

        result = verify_delegation_chain([token_ab, token_bc], card_a)
        assert result.valid is False
        assert "ttl_escalation" in result.reason

    def test_empty_chain(self):
        card = make_card(caps=["carapace:read:email"])
        result = verify_delegation_chain([], card)
        assert result.valid is False
        assert result.reason == "empty_chain"

    def test_expired_link_in_chain(self):
        card_a = make_card(card_id="agent-a", caps=["carapace:read:email"])
        card_b = make_card(card_id="agent-b", caps=[])

        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=8,
            max_redelegation_depth=2,
        )
        token_bc = redelegate(
            parent_token=token_ab,
            redelegator_card=card_b,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # Expire the second link
        token_bc.expires_at = past(1)

        result = verify_delegation_chain([token_ab, token_bc], card_a)
        assert result.valid is False
        assert "expired" in result.reason


# ═══════════════════════════════════════════════════════════════════════════════
# ENFORCEMENT THROUGH DELEGATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnforceDelegated:
    def test_allowed_capability(self):
        card = make_card(caps=["carapace:read:email", "carapace:write:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # Should not raise
        enforce_delegated(token, "carapace:read:email")

    def test_denied_capability(self):
        card = make_card(caps=["carapace:read:email", "carapace:write:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        with pytest.raises(CapabilityEscalation):
            enforce_delegated(token, "carapace:write:email")

    def test_expired_delegation(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        token.expires_at = past(1)
        with pytest.raises(DelegationExpired):
            enforce_delegated(token, "carapace:read:email")

    def test_wildcard_in_delegation(self):
        card = make_card(caps=["carapace:read:*"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:*"],
            ttl_hours=4,
        )
        enforce_delegated(token, "carapace:read:email")  # Covered by wildcard
        enforce_delegated(token, "carapace:read:database")

        with pytest.raises(CapabilityEscalation):
            enforce_delegated(token, "carapace:write:email")


# ═══════════════════════════════════════════════════════════════════════════════
# TOKEN SERIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestTokenSerialization:
    def test_roundtrip(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
            task_context="test task",
        )
        d = token.to_dict()
        d["signature"] = token.signature
        restored = DelegationToken.from_dict(d)
        assert restored.id == token.id
        assert restored.delegated_capabilities == token.delegated_capabilities
        assert restored.task_context == "test task"

    def test_signable_payload_deterministic(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        p1 = token.signable_payload()
        p2 = token.signable_payload()
        assert p1 == p2  # Deterministic

    def test_capabilities_sorted_in_payload(self):
        card = make_card(caps=["carapace:write:email", "carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:write:email", "carapace:read:email"],
            ttl_hours=4,
        )
        # Capabilities should be sorted in the payload
        assert token.delegated_capabilities == [
            "carapace:read:email",
            "carapace:write:email",
        ]
