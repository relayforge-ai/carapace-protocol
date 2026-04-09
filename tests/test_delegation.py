"""
Tests for Carapace v0.3 — Delegation Chains (Python 3.9+)

44 tests covering:
- create_delegation (valid, expired, over depth limit, capability widening rejected)
- verify_delegation_chain (valid chain, revoked parent, expired link)
- validate_capability_subset (wildcards, exact match, superset rejection)
- redelegation depth enforcement
- cascade revocation logic (via card status)

Run: pytest tests/test_delegation.py -v
"""

from __future__ import annotations

import pytest
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from carapace.delegation import (
    DelegationToken,
    DelegationVerifyResult,
    CapabilityEscalation,
    DelegationError,
    DelegationExpired,
    DelegationChainBroken,
    RedelegationDepthExceeded,
    DelegatorCardInvalid,
    TTLExceedsDelegator,
    create_delegation,
    verify_delegation,
    verify_delegation_chain,
    validate_capability_subset,
    narrow_capabilities,
    enforce_delegated,
    redelegate,
    MAX_CHAIN_DEPTH,
    DEFAULT_MAX_TTL_HOURS,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def future(hours: float = 24) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def past(hours: float = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


@dataclass
class MockOwner:
    public_key: str = "aabbccdd" * 8


@dataclass
class MockCard:
    id: str = "agent-a"
    capabilities: list[dict] = field(default_factory=list)
    expires_at: str | None = None
    owner: MockOwner = field(default_factory=MockOwner)
    status: str = "active"


def make_card(
    agent_id: str = "agent-a",
    caps: list[str] | None = None,
    expires_at: str | None = None,
    status: str = "active",
    owner_key: str | None = None,
) -> MockCard:
    capabilities = [{"id": c, "name": c, "description": c} for c in (caps or [])]
    owner = MockOwner(public_key=owner_key or ("aabbccdd" * 8))
    return MockCard(id=agent_id, capabilities=capabilities, expires_at=expires_at, owner=owner, status=status)


def make_token(
    delegator_card_id: str = "agent-a",
    delegate_card_id: str = "agent-b",
    caps: list[str] | None = None,
    expires_at: str | None = None,
    parent_delegation_id: str | None = None,
    max_redelegation_depth: int = 2,
) -> DelegationToken:
    return DelegationToken(
        id="tok-001",
        delegator_card_id=delegator_card_id,
        delegator_public_key="aabbccdd" * 8,
        delegate_card_id=delegate_card_id,
        delegated_capabilities=sorted(caps or ["carapace:read:email"]),
        expires_at=expires_at or future(4),
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        parent_delegation_id=parent_delegation_id,
        max_redelegation_depth=max_redelegation_depth,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATE CAPABILITY SUBSET
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateCapabilitySubset:
    def test_exact_match_passes(self):
        validate_capability_subset(
            ["carapace:read:email"],
            ["carapace:read:email", "carapace:write:email"],
        )

    def test_subset_passes(self):
        validate_capability_subset(
            ["carapace:read:email"],
            ["carapace:read:email", "carapace:write:email", "carapace:delete:email"],
        )

    def test_superset_rejected(self):
        with pytest.raises(CapabilityEscalation):
            validate_capability_subset(
                ["carapace:read:email", "carapace:admin:users"],
                ["carapace:read:email"],
            )

    def test_empty_requested_passes(self):
        validate_capability_subset([], ["carapace:read:email"])

    def test_wildcard_in_available_covers_specific(self):
        validate_capability_subset(
            ["carapace:read:email"],
            ["carapace:read:*"],
        )

    def test_wildcard_in_available_covers_multiple(self):
        validate_capability_subset(
            ["carapace:read:email", "carapace:read:calendar"],
            ["carapace:read:*"],
        )

    def test_wildcard_available_does_not_cover_different_action(self):
        with pytest.raises(CapabilityEscalation):
            validate_capability_subset(
                ["carapace:write:email"],
                ["carapace:read:*"],
            )

    def test_narrowing_wildcard_passes(self):
        # Available has carapace:*, requested has carapace:read:*
        validate_capability_subset(
            ["carapace:read:*"],
            ["carapace:read:*"],
        )

    def test_exact_match_empty_available_fails(self):
        with pytest.raises(CapabilityEscalation):
            validate_capability_subset(["carapace:read:email"], [])

    def test_multiple_capabilities_all_covered(self):
        validate_capability_subset(
            ["carapace:read:email", "carapace:write:email"],
            ["carapace:read:email", "carapace:write:email", "carapace:delete:email"],
        )

    def test_one_of_many_not_covered_fails(self):
        with pytest.raises(CapabilityEscalation):
            validate_capability_subset(
                ["carapace:read:email", "carapace:execute:shell"],
                ["carapace:read:email"],
            )


# ═══════════════════════════════════════════════════════════════════════════════
# CREATE DELEGATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateDelegation:
    def test_valid_basic_delegation(self):
        card = make_card(caps=["carapace:read:email", "carapace:write:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        assert token.delegator_card_id == "agent-a"
        assert token.delegate_card_id == "agent-b"
        assert token.delegated_capabilities == ["carapace:read:email"]
        assert token.max_redelegation_depth == 2  # default

    def test_delegation_sets_nonce(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=1,
        )
        assert len(token.nonce) == 32  # 16 bytes hex = 32 chars

    def test_delegation_sets_created_at(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=1,
        )
        assert token.created_at is not None

    def test_capability_escalation_rejected(self):
        card = make_card(caps=["carapace:read:email"])
        with pytest.raises(CapabilityEscalation):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b",
                capabilities=["carapace:write:database"],
                ttl_hours=4,
            )

    def test_expired_delegator_card_rejected(self):
        card = make_card(caps=["carapace:read:email"], expires_at=past(2))
        with pytest.raises(DelegatorCardInvalid):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b",
                capabilities=["carapace:read:email"],
                ttl_hours=1,
            )

    def test_revoked_delegator_card_rejected(self):
        card = make_card(caps=["carapace:read:email"], status="revoked")
        with pytest.raises(DelegatorCardInvalid):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b",
                capabilities=["carapace:read:email"],
                ttl_hours=1,
            )

    def test_superseded_delegator_card_rejected(self):
        card = make_card(caps=["carapace:read:email"], status="superseded")
        with pytest.raises(DelegatorCardInvalid):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b",
                capabilities=["carapace:read:email"],
                ttl_hours=1,
            )

    def test_ttl_exceeds_delegator_expiry_rejected(self):
        card = make_card(caps=["carapace:read:email"], expires_at=future(2))
        with pytest.raises(TTLExceedsDelegator):
            create_delegation(
                delegator_card=card,
                delegate_card_id="agent-b",
                capabilities=["carapace:read:email"],
                ttl_hours=48,  # exceeds 2h card expiry
            )

    def test_custom_max_redelegation_depth(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=1,
            max_redelegation_depth=0,
        )
        assert token.max_redelegation_depth == 0
        assert not token.can_redelegate

    def test_depth_clamped_to_max_chain_depth(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=1,
            max_redelegation_depth=99,  # Over hard cap
        )
        assert token.max_redelegation_depth == MAX_CHAIN_DEPTH

    def test_task_context_stored(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=1,
            task_context="Process Q2 invoices",
        )
        assert token.task_context == "Process Q2 invoices"

    def test_dict_card_accepted(self):
        card_dict = {
            "id": "agent-a",
            "capabilities": [{"id": "carapace:read:email"}],
            "owner": {"public_key": "aabbccdd" * 8},
            "status": "active",
        }
        token = create_delegation(
            delegator_card=card_dict,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=1,
        )
        assert token.delegator_card_id == "agent-a"

    def test_default_ttl_used_when_no_card_expiry(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
        )
        from carapace.expiry import parse_expires_at
        exp = parse_expires_at(token.expires_at)
        now = datetime.now(timezone.utc)
        # Should be roughly DEFAULT_MAX_TTL_HOURS from now
        assert exp is not None
        diff_hours = (exp - now).total_seconds() / 3600
        assert diff_hours <= DEFAULT_MAX_TTL_HOURS + 0.1


# ═══════════════════════════════════════════════════════════════════════════════
# REDELEGATION DEPTH ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class TestRedelegationDepth:
    def test_redelegation_decrements_depth(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
            max_redelegation_depth=2,
        )
        card_b = make_card("agent-b", caps=["carapace:read:email"])
        token_bc = redelegate(
            parent_token=token_ab,
            redelegator_card=card_b,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],
            ttl_hours=2,
        )
        assert token_bc.max_redelegation_depth == 1  # 2 - 1 = 1

    def test_terminal_delegation_cannot_redelegate(self):
        card = make_card(caps=["carapace:read:email"])
        terminal_token = make_token(
            delegator_card_id="agent-a",
            delegate_card_id="agent-b",
            max_redelegation_depth=0,
        )
        card_b = make_card("agent-b", caps=["carapace:read:email"])
        with pytest.raises(RedelegationDepthExceeded):
            redelegate(
                parent_token=terminal_token,
                redelegator_card=card_b,
                delegate_card_id="agent-c",
                capabilities=["carapace:read:email"],
                ttl_hours=1,
            )

    def test_depth_cannot_exceed_parent_depth(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
            max_redelegation_depth=1,
        )
        card_b = make_card("agent-b", caps=["carapace:read:email"])
        token_bc = redelegate(
            parent_token=token_ab,
            redelegator_card=card_b,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],
            ttl_hours=2,
        )
        # Even if we tried depth=5, it should be capped at parent_depth - 1 = 0
        assert token_bc.max_redelegation_depth == 0


# ═══════════════════════════════════════════════════════════════════════════════
# VERIFY DELEGATION (single token)
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyDelegation:
    def test_valid_delegation(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        result = verify_delegation(token, delegator_card=card)
        assert result.valid is True
        assert result.capabilities == ["carapace:read:email"]

    def test_expired_token_fails(self):
        card = make_card(caps=["carapace:read:email"])
        token = make_token(expires_at=past(1))
        result = verify_delegation(token, delegator_card=card)
        assert result.valid is False
        assert result.reason == "delegation_expired"

    def test_revoked_delegator_card_fails(self):
        card = make_card(caps=["carapace:read:email"], status="revoked")
        token = make_token()
        result = verify_delegation(token, delegator_card=card)
        assert result.valid is False
        assert "revoked" in result.reason

    def test_superseded_delegator_card_fails(self):
        card = make_card(caps=["carapace:read:email"], status="superseded")
        token = make_token()
        result = verify_delegation(token, delegator_card=card)
        assert result.valid is False
        assert "superseded" in result.reason

    def test_capability_escalation_fails(self):
        card = make_card(caps=["carapace:read:email"])
        # Token claims more capabilities than the card has
        token = make_token(caps=["carapace:admin:system"])
        result = verify_delegation(token, delegator_card=card)
        assert result.valid is False
        assert "capability_escalation" in result.reason

    def test_card_id_mismatch_fails(self):
        card = make_card(agent_id="agent-x", caps=["carapace:read:email"])
        token = make_token(delegator_card_id="agent-y")
        result = verify_delegation(token, delegator_card=card)
        assert result.valid is False
        assert "mismatch" in result.reason

    def test_dict_token_accepted(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        result = verify_delegation(token.to_dict() | {"signature": ""}, delegator_card=card)
        assert result.valid is True


# ═══════════════════════════════════════════════════════════════════════════════
# VERIFY DELEGATION CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyDelegationChain:
    def test_single_token_chain(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        result = verify_delegation_chain([token_ab], root_card=card_a)
        assert result.valid is True
        assert result.chain_depth == 1
        assert result.delegate_card_id == "agent-b"

    def test_two_token_chain(self):
        card_a = make_card("agent-a", caps=["carapace:read:email", "carapace:write:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email", "carapace:write:email"],
            ttl_hours=4,
        )
        card_b = make_card("agent-b", caps=["carapace:read:email", "carapace:write:email"])
        token_bc = redelegate(
            parent_token=token_ab,
            redelegator_card=card_b,
            delegate_card_id="agent-c",
            capabilities=["carapace:read:email"],  # narrowed
            ttl_hours=2,
        )
        result = verify_delegation_chain([token_ab, token_bc], root_card=card_a)
        assert result.valid is True
        assert result.chain_depth == 2
        assert result.delegate_card_id == "agent-c"
        assert result.capabilities == ["carapace:read:email"]

    def test_empty_chain_fails(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        result = verify_delegation_chain([], root_card=card_a)
        assert result.valid is False
        assert result.reason == "empty_chain"

    def test_chain_with_expired_root_fails(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"], expires_at=past(2))
        token_ab = make_token(delegator_card_id="agent-a", delegate_card_id="agent-b")
        result = verify_delegation_chain([token_ab], root_card=card_a)
        assert result.valid is False
        assert "root_link_failed" in result.reason

    def test_chain_with_revoked_root_card_fails(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"], status="revoked")
        token_ab = make_token(delegator_card_id="agent-a", delegate_card_id="agent-b")
        result = verify_delegation_chain([token_ab], root_card=card_a)
        assert result.valid is False
        assert "root_link_failed" in result.reason

    def test_broken_parent_reference_fails(self):
        card_a = make_card("agent-a", caps=["carapace:read:email", "carapace:write:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # token_bc claims wrong parent_delegation_id
        token_bc = DelegationToken(
            id="tok-bc",
            delegator_card_id="agent-b",
            delegator_public_key="aabbccdd" * 8,
            delegate_card_id="agent-c",
            delegated_capabilities=["carapace:read:email"],
            expires_at=future(2),
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            parent_delegation_id="wrong-parent-id",
            max_redelegation_depth=1,
        )
        result = verify_delegation_chain([token_ab, token_bc], root_card=card_a)
        assert result.valid is False
        assert "parent_delegation_id mismatch" in result.reason

    def test_capability_escalation_in_chain_fails(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # token_bc claims MORE capabilities than parent
        token_bc = DelegationToken(
            id="tok-bc",
            delegator_card_id="agent-b",
            delegator_public_key="aabbccdd" * 8,
            delegate_card_id="agent-c",
            delegated_capabilities=["carapace:read:email", "carapace:admin:system"],
            expires_at=future(2),
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            parent_delegation_id=token_ab.id,
            max_redelegation_depth=1,
        )
        result = verify_delegation_chain([token_ab, token_bc], root_card=card_a)
        assert result.valid is False
        assert "capability_escalation" in result.reason

    def test_ttl_escalation_in_chain_fails(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=2,
        )
        # token_bc expires AFTER token_ab
        token_bc = DelegationToken(
            id="tok-bc",
            delegator_card_id="agent-b",
            delegator_public_key="aabbccdd" * 8,
            delegate_card_id="agent-c",
            delegated_capabilities=["carapace:read:email"],
            expires_at=future(48),  # Way beyond parent's 2h
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            parent_delegation_id=token_ab.id,
            max_redelegation_depth=1,
        )
        result = verify_delegation_chain([token_ab, token_bc], root_card=card_a)
        assert result.valid is False
        assert "ttl_escalation" in result.reason

    def test_expired_link_in_chain_fails(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # Force token_bc to be already expired
        token_bc = DelegationToken(
            id="tok-bc",
            delegator_card_id="agent-b",
            delegator_public_key="aabbccdd" * 8,
            delegate_card_id="agent-c",
            delegated_capabilities=["carapace:read:email"],
            expires_at=past(1),
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            parent_delegation_id=token_ab.id,
            max_redelegation_depth=1,
        )
        result = verify_delegation_chain([token_ab, token_bc], root_card=card_a)
        assert result.valid is False
        assert "expired" in result.reason

    def test_chain_discontinuity_fails(self):
        """prev delegate must equal current delegator"""
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
        )
        # token_bc has delegator=agent-x, not agent-b
        token_bc = DelegationToken(
            id="tok-bc",
            delegator_card_id="agent-x",  # wrong delegator
            delegator_public_key="aabbccdd" * 8,
            delegate_card_id="agent-c",
            delegated_capabilities=["carapace:read:email"],
            expires_at=future(2),
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            parent_delegation_id=token_ab.id,
            max_redelegation_depth=1,
        )
        result = verify_delegation_chain([token_ab, token_bc], root_card=card_a)
        assert result.valid is False
        assert "discontinuity" in result.reason

    def test_redelegation_depth_exceeded_in_chain(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_ab = create_delegation(
            delegator_card=card_a,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=4,
            max_redelegation_depth=0,  # terminal
        )
        token_bc = DelegationToken(
            id="tok-bc",
            delegator_card_id="agent-b",
            delegator_public_key="aabbccdd" * 8,
            delegate_card_id="agent-c",
            delegated_capabilities=["carapace:read:email"],
            expires_at=future(2),
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            parent_delegation_id=token_ab.id,
            max_redelegation_depth=0,
        )
        result = verify_delegation_chain([token_ab, token_bc], root_card=card_a)
        assert result.valid is False
        assert "redelegation_depth_exceeded" in result.reason

    def test_non_root_first_token_fails(self):
        card_a = make_card("agent-a", caps=["carapace:read:email"])
        token_with_parent = make_token(parent_delegation_id="some-parent-id")
        result = verify_delegation_chain([token_with_parent], root_card=card_a)
        assert result.valid is False
        assert "not_root" in result.reason or "root" in result.reason


# ═══════════════════════════════════════════════════════════════════════════════
# ENFORCE DELEGATED
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnforceDelegated:
    def test_passes_when_capability_present(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=1,
        )
        enforce_delegated(token, "carapace:read:email")  # Should not raise

    def test_raises_when_capability_absent(self):
        card = make_card(caps=["carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:read:email"],
            ttl_hours=1,
        )
        with pytest.raises(CapabilityEscalation):
            enforce_delegated(token, "carapace:write:email")

    def test_raises_when_expired(self):
        token = make_token(expires_at=past(1))
        with pytest.raises(DelegationExpired):
            enforce_delegated(token, "carapace:read:email")


# ═══════════════════════════════════════════════════════════════════════════════
# DELEGATION TOKEN DATACLASS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDelegationToken:
    def test_is_root_true_when_no_parent(self):
        token = make_token(parent_delegation_id=None)
        assert token.is_root is True

    def test_is_root_false_when_has_parent(self):
        token = make_token(parent_delegation_id="parent-uuid")
        assert token.is_root is False

    def test_can_redelegate_true_when_depth_positive(self):
        token = make_token(max_redelegation_depth=1)
        assert token.can_redelegate is True

    def test_can_redelegate_false_when_depth_zero(self):
        token = make_token(max_redelegation_depth=0)
        assert token.can_redelegate is False

    def test_to_dict_excludes_signature(self):
        token = make_token()
        d = token.to_dict()
        assert "signature" not in d

    def test_round_trip_from_dict(self):
        original = make_token()
        original.signature = "deadbeef" * 16
        d = {**original.to_dict(), "signature": original.signature}
        restored = DelegationToken.from_dict(d)
        assert restored.id == original.id
        assert restored.delegated_capabilities == original.delegated_capabilities
        assert restored.signature == original.signature

    def test_signable_payload_is_deterministic(self):
        token = make_token()
        p1 = token.signable_payload()
        p2 = token.signable_payload()
        assert p1 == p2

    def test_capabilities_sorted_in_token(self):
        card = make_card(caps=["carapace:write:email", "carapace:read:email"])
        token = create_delegation(
            delegator_card=card,
            delegate_card_id="agent-b",
            capabilities=["carapace:write:email", "carapace:read:email"],
            ttl_hours=1,
        )
        assert token.delegated_capabilities == sorted(token.delegated_capabilities)
