"""
Carapace v0.2 — Runtime Capability Enforcement

Middleware layer that gates API/tool calls based on declared capability scope.
This is what makes the capability taxonomy load-bearing rather than decorative.

Usage:
    from carapace.enforce import enforce, CapabilityDenied

    # Throws CapabilityDenied if the card doesn't declare the required capability
    enforce(card, "carapace:write:database")

    # Or use as a decorator / guard
    @require_capability("carapace:execute:process_control")
    def run_process_command(card, command):
        ...

    # Batch check (all must be present)
    enforce_all(card, ["carapace:read:email", "carapace:write:email"])

    # Check without throwing
    has = has_capability(card, "carapace:read:email")  # -> bool
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Protocol, Sequence, runtime_checkable


# ── Exceptions ────────────────────────────────────────────────────────────────

class CapabilityDenied(Exception):
    """Raised when an agent card lacks a required capability."""

    def __init__(
        self,
        required: str,
        agent_id: str | None = None,
        declared: list[str] | None = None,
    ):
        self.required = required
        self.agent_id = agent_id
        self.declared = declared or []
        msg = f"Capability denied: '{required}' not declared"
        if agent_id:
            msg += f" by agent {agent_id}"
        super().__init__(msg)


class CardExpired(Exception):
    """Raised when enforcement is attempted on an expired card."""

    def __init__(self, agent_id: str | None = None, expires_at: str | None = None):
        self.agent_id = agent_id
        self.expires_at = expires_at
        msg = "Card expired"
        if agent_id:
            msg += f" for agent {agent_id}"
        if expires_at:
            msg += f" (expired at {expires_at})"
        super().__init__(msg)


# ── Card Protocol ─────────────────────────────────────────────────────────────
# Accepts any object that looks like an AgentCard — duck typing so this works
# with both the Python and any external card representations.

@runtime_checkable
class CardLike(Protocol):
    """Minimum shape needed for enforcement. AgentCard satisfies this."""
    id: str | None
    capabilities: list[dict[str, Any]]
    expires_at: str | None  # ISO 8601 or None


# ── Core Enforcement ──────────────────────────────────────────────────────────

def _extract_capability_ids(card: Any) -> list[str]:
    """Pull capability IDs from a card, handling both dict and object forms."""
    caps = getattr(card, "capabilities", None) or []
    if isinstance(caps, list):
        return [
            c["id"] if isinstance(c, dict) else getattr(c, "id", "")
            for c in caps
        ]
    return []


def _check_expiry(card: Any) -> None:
    """Raise CardExpired if the card's TTL has passed."""
    expires_at = getattr(card, "expires_at", None)
    if expires_at is None:
        return

    if isinstance(expires_at, str):
        try:
            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return  # Malformed expiry — don't block, let verify() catch it
    elif isinstance(expires_at, datetime):
        exp_dt = expires_at
    else:
        return

    if exp_dt.tzinfo is None:
        exp_dt = exp_dt.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    if now > exp_dt:
        raise CardExpired(
            agent_id=getattr(card, "id", None),
            expires_at=str(expires_at),
        )


def has_capability(card: Any, required: str) -> bool:
    """
    Check if a card declares a capability. Supports exact match and
    wildcard prefix matching.

    Examples:
        has_capability(card, "carapace:read:email")           # exact
        has_capability(card, "carapace:read:*")                # any read
        has_capability(card, "carapace:*")                     # any carapace action
    """
    declared = _extract_capability_ids(card)

    # Exact match
    if required in declared:
        return True

    # Wildcard in the REQUIRED param (host is saying "any read capability")
    if required.endswith(":*"):
        prefix = required[:-1]  # "carapace:read:"
        return any(d.startswith(prefix) for d in declared)

    # Wildcard in DECLARED caps (agent registered "carapace:read:*")
    for d in declared:
        if d.endswith(":*"):
            prefix = d[:-1]
            if required.startswith(prefix):
                return True

    return False


def enforce(card: Any, required: str, *, check_expiry: bool = True) -> None:
    """
    Enforce that a card declares the required capability.
    Throws CapabilityDenied if not. Checks expiry first by default.

    This is the core function — call it before every tool invocation:

        enforce(card, "carapace:write:database")
        # If we get here, the card is valid and declares the capability
        execute_db_write(...)
    """
    if check_expiry:
        _check_expiry(card)

    if not has_capability(card, required):
        raise CapabilityDenied(
            required=required,
            agent_id=getattr(card, "id", None),
            declared=_extract_capability_ids(card),
        )


def enforce_all(
    card: Any,
    required: Sequence[str],
    *,
    check_expiry: bool = True,
) -> None:
    """Enforce that ALL listed capabilities are declared. Fails on first miss."""
    if check_expiry:
        _check_expiry(card)
    for cap in required:
        enforce(card, cap, check_expiry=False)  # Already checked


def enforce_any(
    card: Any,
    required: Sequence[str],
    *,
    check_expiry: bool = True,
) -> None:
    """Enforce that AT LEAST ONE of the listed capabilities is declared."""
    if check_expiry:
        _check_expiry(card)
    for cap in required:
        if has_capability(card, cap):
            return
    raise CapabilityDenied(
        required=f"any of [{', '.join(required)}]",
        agent_id=getattr(card, "id", None),
        declared=_extract_capability_ids(card),
    )


# ── Decorator ─────────────────────────────────────────────────────────────────

def require_capability(*capabilities: str, check_expiry: bool = True):
    """
    Decorator that enforces capabilities before function execution.
    The decorated function's first argument must be a card-like object.

    @require_capability("carapace:write:database")
    def write_record(card, data):
        ...

    @require_capability("carapace:read:email", "carapace:write:email")
    def sync_mailbox(card, config):
        ...
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(card: Any, *args: Any, **kwargs: Any) -> Any:
            enforce_all(card, capabilities, check_expiry=check_expiry)
            return fn(card, *args, **kwargs)
        return wrapper
    return decorator


# ── Enforcement Policy ────────────────────────────────────────────────────────
# Pre-built policies for common gate patterns.

@dataclass
class EnforcementPolicy:
    """
    A named enforcement policy that maps tool/action names to required
    capabilities. Use this to define a host system's access control rules
    in one place.

    policy = EnforcementPolicy(
        name="email-service",
        rules={
            "read_inbox":   ["carapace:read:email"],
            "send_email":   ["carapace:write:email"],
            "delete_email": ["carapace:delete:email"],
        }
    )

    policy.enforce(card, "send_email")  # Checks carapace:write:email
    """
    name: str
    rules: dict[str, list[str]] = field(default_factory=dict)

    def enforce(self, card: Any, action: str) -> None:
        """Enforce the capabilities required for a specific action."""
        required = self.rules.get(action)
        if required is None:
            raise ValueError(
                f"Unknown action '{action}' in policy '{self.name}'. "
                f"Known actions: {list(self.rules.keys())}"
            )
        enforce_all(card, required)

    def has_access(self, card: Any, action: str) -> bool:
        """Non-throwing check for action access."""
        required = self.rules.get(action)
        if required is None:
            return False
        return all(has_capability(card, r) for r in required)

    def audit_card(self, card: Any) -> dict[str, bool]:
        """Return which actions this card can and can't perform."""
        return {
            action: self.has_access(card, action)
            for action in self.rules
        }
