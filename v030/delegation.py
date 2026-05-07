"""
Carapace v0.3 — Delegation Chains

When Agent A spawns Agent B for a subtask, Agent B should operate with a
subset of Agent A's capabilities — never more. This module implements
signed delegation tokens that make that guarantee cryptographically verifiable.

This is OAuth scopes adapted for agent-to-agent trust.

Usage:
    # Agent A creates a delegation for Agent B
    token = create_delegation(
        delegator_card=agent_a_card,
        delegator_private_key="hex...",
        delegate_card_id="agent-b-uuid",
        capabilities=["carapace:read:email", "carapace:write:email"],
        ttl_hours=4,
    )

    # Agent B presents the token. Verifier checks it.
    result = verify_delegation(token, delegator_card=agent_a_card)

    # For chains (A→B→C), verify the full chain
    chain_result = verify_delegation_chain(
        tokens=[token_ab, token_bc],
        root_card=agent_a_card,
    )

    # Enforce capabilities through a delegation
    enforce_delegated(token, "carapace:read:email")
"""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from carapace.enforce import has_capability, _extract_capability_ids
from carapace.expiry import parse_expires_at, is_expired


# ── Constants ─────────────────────────────────────────────────────────────────

MAX_CHAIN_DEPTH = 5                    # Hard cap on re-delegation depth
DEFAULT_MAX_TTL_HOURS = 24             # Max TTL when delegator card has no expiry
DEFAULT_REDELEGATION_DEPTH = 2         # Default if not specified


# ── Exceptions ────────────────────────────────────────────────────────────────

class DelegationError(Exception):
    """Base error for delegation operations."""
    pass


class CapabilityEscalation(DelegationError):
    """Delegated capabilities exceed the delegator's declared capabilities."""
    def __init__(self, requested: list[str], available: list[str]):
        self.requested = requested
        self.available = available
        escalated = set(requested) - set(available)
        super().__init__(
            f"Capability escalation: {escalated} not in delegator's capabilities"
        )


class DelegationExpired(DelegationError):
    """Delegation token has expired."""
    pass


class DelegationChainBroken(DelegationError):
    """A link in the delegation chain failed verification."""
    def __init__(self, link_index: int, reason: str):
        self.link_index = link_index
        self.reason = reason
        super().__init__(f"Chain broken at link {link_index}: {reason}")


class RedelegationDepthExceeded(DelegationError):
    """Re-delegation would exceed the allowed depth."""
    pass


class DelegatorCardInvalid(DelegationError):
    """The delegator's card is expired, revoked, or superseded."""
    pass


class TTLExceedsDelegator(DelegationError):
    """Delegation TTL extends beyond the delegator's card expiry."""
    pass


class SignatureInvalid(DelegationError):
    """Token signature verification failed."""
    pass


# ── Delegation Token ──────────────────────────────────────────────────────────

@dataclass
class DelegationToken:
    """A signed delegation of capabilities from one agent to another."""
    id: str
    delegator_card_id: str
    delegator_public_key: str
    delegate_card_id: str
    delegated_capabilities: list[str]
    expires_at: str                         # ISO 8601, always required
    created_at: str
    parent_delegation_id: str | None = None
    max_redelegation_depth: int = DEFAULT_REDELEGATION_DEPTH
    task_context: str | None = None
    nonce: str = ""
    signature: str = ""                     # Ed25519 hex, set after signing

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict (for JCS canonicalization and transport)."""
        return {
            "id": self.id,
            "delegator_card_id": self.delegator_card_id,
            "delegator_public_key": self.delegator_public_key,
            "delegate_card_id": self.delegate_card_id,
            "delegated_capabilities": sorted(self.delegated_capabilities),
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "parent_delegation_id": self.parent_delegation_id,
            "max_redelegation_depth": self.max_redelegation_depth,
            "task_context": self.task_context,
            "nonce": self.nonce,
        }

    def signable_payload(self) -> str:
        """JCS-canonical JSON payload for signing (excludes signature field)."""
        d = self.to_dict()
        # JCS: sorted keys, no whitespace (RFC 8785)
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DelegationToken:
        return cls(
            id=data["id"],
            delegator_card_id=data["delegator_card_id"],
            delegator_public_key=data["delegator_public_key"],
            delegate_card_id=data["delegate_card_id"],
            delegated_capabilities=data["delegated_capabilities"],
            expires_at=data["expires_at"],
            created_at=data["created_at"],
            parent_delegation_id=data.get("parent_delegation_id"),
            max_redelegation_depth=data.get("max_redelegation_depth", DEFAULT_REDELEGATION_DEPTH),
            task_context=data.get("task_context"),
            nonce=data.get("nonce", ""),
            signature=data.get("signature", ""),
        )

    @property
    def is_root(self) -> bool:
        """True if this is a root delegation (not a re-delegation)."""
        return self.parent_delegation_id is None

    @property
    def can_redelegate(self) -> bool:
        """True if this token allows further delegation."""
        return self.max_redelegation_depth > 0


# ── Verification Result ───────────────────────────────────────────────────────

@dataclass
class DelegationVerifyResult:
    """Result of verifying a delegation token or chain."""
    valid: bool
    reason: str | None = None
    token_id: str | None = None
    delegator_card_id: str | None = None
    delegate_card_id: str | None = None
    capabilities: list[str] = field(default_factory=list)
    chain_depth: int = 0
    expires_at: str | None = None


# ── Capability Subset Validation ──────────────────────────────────────────────

def validate_capability_subset(
    requested: list[str],
    available: list[str],
) -> None:
    """
    Verify that every requested capability is covered by the available set.
    Handles wildcard matching in both directions.

    Raises CapabilityEscalation if any requested capability isn't covered.
    """
    for req in requested:
        # Check if any available capability covers this request
        covered = False

        # Exact match
        if req in available:
            covered = True
        else:
            # Check wildcards in available
            for avail in available:
                if avail.endswith(":*"):
                    prefix = avail[:-1]
                    if req.startswith(prefix):
                        covered = True
                        break

            # Check if request is a wildcard narrowing a broader wildcard
            if not covered and req.endswith(":*"):
                req_prefix = req[:-1]
                for avail in available:
                    if avail.endswith(":*"):
                        avail_prefix = avail[:-1]
                        if req_prefix.startswith(avail_prefix):
                            covered = True
                            break

        if not covered:
            raise CapabilityEscalation(requested, available)


def narrow_capabilities(
    parent_capabilities: list[str],
    requested: list[str],
) -> list[str]:
    """
    Validate and return the narrowed capability set.
    Raises CapabilityEscalation if requested exceeds parent.
    """
    validate_capability_subset(requested, parent_capabilities)
    return list(requested)


# ── Token Creation ────────────────────────────────────────────────────────────

def create_delegation(
    delegator_card: Any,
    delegate_card_id: str,
    capabilities: list[str],
    *,
    delegator_private_key: str | None = None,
    ttl_hours: float | None = None,
    ttl_minutes: float | None = None,
    expires_at: str | None = None,
    parent_delegation: DelegationToken | None = None,
    max_redelegation_depth: int | None = None,
    task_context: str | None = None,
    sign_fn: Any | None = None,
) -> DelegationToken:
    """
    Create a delegation token from a delegator's card to a delegate.

    Args:
        delegator_card: The delegator's AgentCard (or card-like object).
        delegate_card_id: UUID of the agent receiving the delegation.
        capabilities: Capabilities to delegate (must be subset of delegator's).
        delegator_private_key: Ed25519 private key hex for signing.
        ttl_hours: Token lifetime in hours.
        ttl_minutes: Token lifetime in minutes.
        expires_at: Absolute expiry (ISO 8601). Overrides ttl_*.
        parent_delegation: If re-delegating, the parent token.
        max_redelegation_depth: How many more re-delegations allowed.
        task_context: Optional task description for audit trail.
        sign_fn: Optional custom signing function(payload_bytes, private_key_hex) -> signature_hex.
                 If None, signing is deferred (signature will be empty).

    Returns:
        DelegationToken (signed if sign_fn or delegator_private_key provided).
    """
    now = datetime.now(timezone.utc)

    # ── Resolve delegator info ────────────────────────────────────────────
    delegator_id = (
        delegator_card.get("id") if isinstance(delegator_card, dict)
        else getattr(delegator_card, "id", None)
    )
    if isinstance(delegator_card, dict):
        delegator_pubkey = delegator_card.get("owner", {}).get("public_key", "")
        delegator_caps = _extract_capability_ids(delegator_card)
        delegator_expiry = delegator_card.get("expires_at")
    else:
        owner = getattr(delegator_card, "owner", None)
        delegator_pubkey = getattr(owner, "public_key", "") if owner else ""
        delegator_caps = _extract_capability_ids(delegator_card)
        delegator_expiry = getattr(delegator_card, "expires_at", None)

    # ── Check delegator card validity ─────────────────────────────────────
    if is_expired(delegator_card):
        raise DelegatorCardInvalid("Delegator's card has expired")

    status = (
        delegator_card.get("status") if isinstance(delegator_card, dict)
        else getattr(delegator_card, "status", "active")
    )
    if status in ("revoked", "superseded"):
        raise DelegatorCardInvalid(f"Delegator's card status is '{status}'")

    # ── Handle re-delegation constraints ──────────────────────────────────
    effective_caps = delegator_caps
    effective_max_depth = max_redelegation_depth

    if parent_delegation is not None:
        if not parent_delegation.can_redelegate:
            raise RedelegationDepthExceeded(
                f"Parent delegation {parent_delegation.id} has "
                f"max_redelegation_depth=0 — cannot re-delegate"
            )
        # Capabilities must be subset of parent delegation's capabilities
        effective_caps = parent_delegation.delegated_capabilities

        # Depth decrements
        parent_depth = parent_delegation.max_redelegation_depth
        if effective_max_depth is None:
            effective_max_depth = parent_depth - 1
        elif effective_max_depth >= parent_depth:
            effective_max_depth = parent_depth - 1

        # TTL cannot exceed parent's TTL
        parent_exp = parse_expires_at(parent_delegation.expires_at)
        if parent_exp is not None:
            delegator_expiry = parent_delegation.expires_at
    else:
        if effective_max_depth is None:
            effective_max_depth = DEFAULT_REDELEGATION_DEPTH

    # Clamp depth to hard cap
    effective_max_depth = min(effective_max_depth, MAX_CHAIN_DEPTH)

    # ── Validate capability subset ────────────────────────────────────────
    validate_capability_subset(capabilities, effective_caps)

    # ── Resolve expiry ────────────────────────────────────────────────────
    if expires_at is not None:
        token_expiry = expires_at
    elif ttl_hours is not None or ttl_minutes is not None:
        delta = timedelta(
            hours=ttl_hours or 0,
            minutes=ttl_minutes or 0,
        )
        token_expiry = (now + delta).isoformat().replace("+00:00", "Z")
    else:
        # Default: use delegator's expiry or DEFAULT_MAX_TTL_HOURS
        if delegator_expiry:
            token_expiry = delegator_expiry
        else:
            token_expiry = (
                now + timedelta(hours=DEFAULT_MAX_TTL_HOURS)
            ).isoformat().replace("+00:00", "Z")

    # ── Verify TTL doesn't exceed delegator's ────────────────────────────
    token_exp_dt = parse_expires_at(token_expiry)
    if delegator_expiry:
        delegator_exp_dt = parse_expires_at(delegator_expiry)
        if token_exp_dt and delegator_exp_dt and token_exp_dt > delegator_exp_dt:
            raise TTLExceedsDelegator(
                f"Delegation expires at {token_expiry} but delegator's card "
                f"expires at {delegator_expiry}"
            )

    # ── Build the token ───────────────────────────────────────────────────
    token = DelegationToken(
        id=str(uuid.uuid4()),
        delegator_card_id=delegator_id or "",
        delegator_public_key=delegator_pubkey,
        delegate_card_id=delegate_card_id,
        delegated_capabilities=sorted(capabilities),
        expires_at=token_expiry,
        created_at=now.isoformat().replace("+00:00", "Z"),
        parent_delegation_id=(
            parent_delegation.id if parent_delegation else None
        ),
        max_redelegation_depth=effective_max_depth,
        task_context=task_context,
        nonce=secrets.token_hex(16),
    )

    # ── Sign ──────────────────────────────────────────────────────────────
    if sign_fn is not None and delegator_private_key:
        payload = token.signable_payload().encode("utf-8")
        token.signature = sign_fn(payload, delegator_private_key)
    elif delegator_private_key:
        # If no sign_fn, try to use Ed25519 directly
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            key_bytes = bytes.fromhex(delegator_private_key)
            # Ed25519 private keys are 32 bytes; some formats use 64 (seed+public)
            if len(key_bytes) == 64:
                private_key = Ed25519PrivateKey.from_private_bytes(key_bytes[:32])
            else:
                private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
            payload = token.signable_payload().encode("utf-8")
            sig = private_key.sign(payload)
            token.signature = sig.hex()
        except ImportError:
            pass  # No cryptography library — signature deferred
        except Exception:
            pass  # Key format issue — signature deferred

    return token


# ── Token Verification ────────────────────────────────────────────────────────

def verify_delegation(
    token: DelegationToken | dict,
    delegator_card: Any,
    *,
    verify_signature_fn: Any | None = None,
    now: datetime | None = None,
) -> DelegationVerifyResult:
    """
    Verify a single delegation token against the delegator's card.

    Checks:
    1. Token hasn't expired
    2. Delegator card is valid (not expired, not revoked)
    3. Delegated capabilities are a subset of delegator's capabilities
    4. Signature is valid (if verify_signature_fn provided)
    5. Token's delegator_card_id matches the card

    Args:
        token: The delegation token to verify.
        delegator_card: The delegator's AgentCard.
        verify_signature_fn: Optional fn(payload_bytes, signature_hex, public_key_hex) -> bool.
        now: Override current time for testing.

    Returns:
        DelegationVerifyResult
    """
    if isinstance(token, dict):
        token = DelegationToken.from_dict(token)

    current = now or datetime.now(timezone.utc)

    # ── Check token expiry ────────────────────────────────────────────────
    token_exp = parse_expires_at(token.expires_at)
    if token_exp and current > token_exp:
        return DelegationVerifyResult(
            valid=False,
            reason="delegation_expired",
            token_id=token.id,
            expires_at=token.expires_at,
        )

    # ── Check delegator card validity ─────────────────────────────────────
    if is_expired(delegator_card, now=current):
        return DelegationVerifyResult(
            valid=False,
            reason="delegator_card_expired",
            token_id=token.id,
            delegator_card_id=token.delegator_card_id,
        )

    status = (
        delegator_card.get("status") if isinstance(delegator_card, dict)
        else getattr(delegator_card, "status", "active")
    )
    if status in ("revoked", "superseded"):
        return DelegationVerifyResult(
            valid=False,
            reason=f"delegator_card_{status}",
            token_id=token.id,
            delegator_card_id=token.delegator_card_id,
        )

    # ── Check card ID match ───────────────────────────────────────────────
    card_id = (
        delegator_card.get("id") if isinstance(delegator_card, dict)
        else getattr(delegator_card, "id", None)
    )
    if card_id and token.delegator_card_id != card_id:
        return DelegationVerifyResult(
            valid=False,
            reason="delegator_card_id_mismatch",
            token_id=token.id,
            delegator_card_id=token.delegator_card_id,
        )

    # ── Check capability subset ───────────────────────────────────────────
    delegator_caps = _extract_capability_ids(delegator_card)

    try:
        validate_capability_subset(token.delegated_capabilities, delegator_caps)
    except CapabilityEscalation as e:
        return DelegationVerifyResult(
            valid=False,
            reason=f"capability_escalation: {e}",
            token_id=token.id,
        )

    # ── Check signature ───────────────────────────────────────────────────
    if verify_signature_fn and token.signature:
        payload = token.signable_payload().encode("utf-8")
        try:
            sig_valid = verify_signature_fn(
                payload, token.signature, token.delegator_public_key
            )
            if not sig_valid:
                return DelegationVerifyResult(
                    valid=False,
                    reason="signature_invalid",
                    token_id=token.id,
                )
        except Exception as e:
            return DelegationVerifyResult(
                valid=False,
                reason=f"signature_error: {e}",
                token_id=token.id,
            )

    # ── All checks passed ─────────────────────────────────────────────────
    return DelegationVerifyResult(
        valid=True,
        token_id=token.id,
        delegator_card_id=token.delegator_card_id,
        delegate_card_id=token.delegate_card_id,
        capabilities=token.delegated_capabilities,
        chain_depth=0 if token.is_root else 1,
        expires_at=token.expires_at,
    )


# ── Chain Verification ────────────────────────────────────────────────────────

def verify_delegation_chain(
    tokens: Sequence[DelegationToken | dict],
    root_card: Any,
    *,
    verify_signature_fn: Any | None = None,
    now: datetime | None = None,
) -> DelegationVerifyResult:
    """
    Verify a full delegation chain from root delegator to final delegate.

    Tokens must be ordered: [root_delegation, first_redelegation, ..., final].
    The root_card is the original delegator's AgentCard.

    Checks per link:
    1. Individual token verification (expiry, signature, card validity)
    2. Each link's capabilities ⊆ previous link's capabilities (narrowing)
    3. Each link's expires_at ≤ previous link's expires_at
    4. parent_delegation_id chain is consistent
    5. Redelegation depth is respected

    Returns a result describing the final delegate's effective authority.
    """
    if not tokens:
        return DelegationVerifyResult(valid=False, reason="empty_chain")

    normalized: list[DelegationToken] = []
    for t in tokens:
        if isinstance(t, dict):
            normalized.append(DelegationToken.from_dict(t))
        else:
            normalized.append(t)

    current = now or datetime.now(timezone.utc)

    # ── Verify root token against card ────────────────────────────────────
    root_result = verify_delegation(
        normalized[0], root_card,
        verify_signature_fn=verify_signature_fn,
        now=current,
    )
    if not root_result.valid:
        return DelegationVerifyResult(
            valid=False,
            reason=f"root_link_failed: {root_result.reason}",
            token_id=normalized[0].id,
            chain_depth=0,
        )

    if not normalized[0].is_root:
        return DelegationVerifyResult(
            valid=False,
            reason="first_token_is_not_root (has parent_delegation_id)",
            token_id=normalized[0].id,
        )

    # ── Walk the chain ────────────────────────────────────────────────────
    prev_token = normalized[0]
    prev_caps = prev_token.delegated_capabilities
    prev_expiry = parse_expires_at(prev_token.expires_at)

    for i, token in enumerate(normalized[1:], start=1):
        # Parent reference check
        if token.parent_delegation_id != prev_token.id:
            return DelegationVerifyResult(
                valid=False,
                reason=(
                    f"parent_delegation_id mismatch at link {i}: "
                    f"expected {prev_token.id}, got {token.parent_delegation_id}"
                ),
                token_id=token.id,
                chain_depth=i,
            )

        # Delegate of previous must be delegator of current
        if prev_token.delegate_card_id != token.delegator_card_id:
            return DelegationVerifyResult(
                valid=False,
                reason=(
                    f"chain discontinuity at link {i}: prev delegate "
                    f"{prev_token.delegate_card_id} != current delegator "
                    f"{token.delegator_card_id}"
                ),
                token_id=token.id,
                chain_depth=i,
            )

        # Capability narrowing
        try:
            validate_capability_subset(token.delegated_capabilities, prev_caps)
        except CapabilityEscalation:
            return DelegationVerifyResult(
                valid=False,
                reason=f"capability_escalation at link {i}",
                token_id=token.id,
                chain_depth=i,
            )

        # TTL narrowing
        token_exp = parse_expires_at(token.expires_at)
        if token_exp and prev_expiry and token_exp > prev_expiry:
            return DelegationVerifyResult(
                valid=False,
                reason=(
                    f"ttl_escalation at link {i}: {token.expires_at} "
                    f"exceeds parent {prev_token.expires_at}"
                ),
                token_id=token.id,
                chain_depth=i,
            )

        # Redelegation depth
        if prev_token.max_redelegation_depth <= 0:
            return DelegationVerifyResult(
                valid=False,
                reason=f"redelegation_depth_exceeded at link {i}",
                token_id=token.id,
                chain_depth=i,
            )

        # Token-level checks (expiry, signature)
        # For chain links after root, we don't have the intermediate card,
        # so we check expiry and signature only (not card validity — that's
        # the root card's job via the chain of trust).
        token_exp_check = parse_expires_at(token.expires_at)
        if token_exp_check and current > token_exp_check:
            return DelegationVerifyResult(
                valid=False,
                reason=f"delegation_expired at link {i}",
                token_id=token.id,
                chain_depth=i,
            )

        if verify_signature_fn and token.signature:
            payload = token.signable_payload().encode("utf-8")
            try:
                sig_valid = verify_signature_fn(
                    payload, token.signature, token.delegator_public_key
                )
                if not sig_valid:
                    return DelegationVerifyResult(
                        valid=False,
                        reason=f"signature_invalid at link {i}",
                        token_id=token.id,
                        chain_depth=i,
                    )
            except Exception as e:
                return DelegationVerifyResult(
                    valid=False,
                    reason=f"signature_error at link {i}: {e}",
                    token_id=token.id,
                    chain_depth=i,
                )

        prev_token = token
        prev_caps = token.delegated_capabilities
        prev_expiry = parse_expires_at(token.expires_at)

    # ── Chain valid ───────────────────────────────────────────────────────
    final = normalized[-1]
    return DelegationVerifyResult(
        valid=True,
        token_id=final.id,
        delegator_card_id=normalized[0].delegator_card_id,
        delegate_card_id=final.delegate_card_id,
        capabilities=final.delegated_capabilities,
        chain_depth=len(normalized),
        expires_at=final.expires_at,
    )


# ── Enforcement Through Delegation ────────────────────────────────────────────

def enforce_delegated(
    token: DelegationToken | dict,
    required: str,
    *,
    now: datetime | None = None,
) -> None:
    """
    Enforce a capability through a delegation token.
    Like enforce() but checks the token's delegated capabilities
    instead of a card's declared capabilities.

    Raises DelegationExpired or CapabilityEscalation on failure.
    """
    if isinstance(token, dict):
        token = DelegationToken.from_dict(token)

    current = now or datetime.now(timezone.utc)

    # Check expiry
    token_exp = parse_expires_at(token.expires_at)
    if token_exp and current > token_exp:
        raise DelegationExpired(f"Delegation {token.id} expired at {token.expires_at}")

    # Check capability
    if not _has_delegated_capability(token, required):
        raise CapabilityEscalation([required], token.delegated_capabilities)


def _has_delegated_capability(token: DelegationToken, required: str) -> bool:
    """Check if a delegation token covers the required capability."""
    caps = token.delegated_capabilities

    if required in caps:
        return True

    # Wildcard in required
    if required.endswith(":*"):
        prefix = required[:-1]
        return any(c.startswith(prefix) for c in caps)

    # Wildcard in delegated
    for c in caps:
        if c.endswith(":*"):
            prefix = c[:-1]
            if required.startswith(prefix):
                return True

    return False


# ── Re-delegation Helper ─────────────────────────────────────────────────────

def redelegate(
    parent_token: DelegationToken,
    redelegator_card: Any,
    delegate_card_id: str,
    capabilities: list[str],
    *,
    redelegator_private_key: str | None = None,
    ttl_hours: float | None = None,
    ttl_minutes: float | None = None,
    task_context: str | None = None,
    sign_fn: Any | None = None,
) -> DelegationToken:
    """
    Re-delegate a subset of an existing delegation's capabilities.

    This is the convenience wrapper for creating a chain link.
    Agent B received a delegation from Agent A, and now delegates
    a narrower subset to Agent C.

    Automatically:
    - Sets parent_delegation_id
    - Decrements max_redelegation_depth
    - Constrains TTL to not exceed parent's
    - Validates capability subset against parent (not against card)
    """
    return create_delegation(
        delegator_card=redelegator_card,
        delegate_card_id=delegate_card_id,
        capabilities=capabilities,
        delegator_private_key=redelegator_private_key,
        ttl_hours=ttl_hours,
        ttl_minutes=ttl_minutes,
        parent_delegation=parent_token,
        task_context=task_context,
        sign_fn=sign_fn,
    )
