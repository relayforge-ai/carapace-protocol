"""
Carapace v0.2 — Card Expiry / TTL

Adds expires_at support to the agent card lifecycle.
One schema field, huge enterprise signal (SOC 2, FedRAMP).

This module provides:
- TTL validation for verify() and verifyLocal() integration
- Helper functions for creating cards with expiry
- Expiry status checking without full verification
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ExpiryStatus(Enum):
    """Card expiry states."""
    VALID = "valid"              # Not expired, or no expiry set
    EXPIRED = "expired"          # Past expires_at
    EXPIRING_SOON = "expiring_soon"  # Within warning threshold
    NO_EXPIRY = "no_expiry"      # No expires_at field (v0.1.1 behavior)


# ── Expiry Helpers ────────────────────────────────────────────────────────────

def make_expires_at(
    ttl_hours: int | None = None,
    ttl_days: int | None = None,
    absolute: datetime | str | None = None,
) -> str | None:
    """
    Produce an ISO 8601 expires_at value for card registration.

    Usage:
        # Relative TTL
        expires = make_expires_at(ttl_hours=24)
        expires = make_expires_at(ttl_days=90)

        # Absolute deadline
        expires = make_expires_at(absolute="2026-12-31T23:59:59Z")
        expires = make_expires_at(absolute=datetime(2026, 12, 31, tzinfo=timezone.utc))

    Returns ISO 8601 string or None.
    """
    if absolute is not None:
        if isinstance(absolute, str):
            return absolute
        if isinstance(absolute, datetime):
            if absolute.tzinfo is None:
                absolute = absolute.replace(tzinfo=timezone.utc)
            return absolute.isoformat().replace("+00:00", "Z")
        raise TypeError(f"absolute must be str or datetime, got {type(absolute)}")

    if ttl_hours is not None or ttl_days is not None:
        delta = timedelta(
            hours=ttl_hours or 0,
            days=ttl_days or 0,
        )
        if delta.total_seconds() <= 0:
            raise ValueError("TTL must be positive")
        expires = datetime.now(timezone.utc) + delta
        return expires.isoformat().replace("+00:00", "Z")

    return None  # No expiry


def parse_expires_at(value: Any) -> datetime | None:
    """Parse an expires_at value to a timezone-aware datetime, or None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None
    return None


def check_expiry(
    card: Any,
    *,
    warning_threshold: timedelta = timedelta(hours=24),
    now: datetime | None = None,
) -> ExpiryStatus:
    """
    Check a card's expiry status without performing full verification.

    Args:
        card: AgentCard or dict with optional expires_at field.
        warning_threshold: How far in advance to flag EXPIRING_SOON.
        now: Override current time (for testing).

    Returns:
        ExpiryStatus enum value.
    """
    raw = (
        card.get("expires_at") if isinstance(card, dict)
        else getattr(card, "expires_at", None)
    )
    expires_dt = parse_expires_at(raw)

    if expires_dt is None:
        return ExpiryStatus.NO_EXPIRY

    current = now or datetime.now(timezone.utc)

    if current > expires_dt:
        return ExpiryStatus.EXPIRED

    if current > (expires_dt - warning_threshold):
        return ExpiryStatus.EXPIRING_SOON

    return ExpiryStatus.VALID


def is_expired(card: Any, *, now: datetime | None = None) -> bool:
    """Quick boolean check: is the card past its TTL?"""
    return check_expiry(card, now=now) == ExpiryStatus.EXPIRED


def time_remaining(card: Any, *, now: datetime | None = None) -> timedelta | None:
    """
    Time remaining before card expires. None if no expiry set.
    Negative timedelta if already expired.
    """
    raw = (
        card.get("expires_at") if isinstance(card, dict)
        else getattr(card, "expires_at", None)
    )
    expires_dt = parse_expires_at(raw)

    if expires_dt is None:
        return None

    current = now or datetime.now(timezone.utc)
    return expires_dt - current


# ── Verify Integration ────────────────────────────────────────────────────────
# These functions are meant to be called from within verify() / verifyLocal()
# as additional checks layered on top of signature verification.

def validate_expiry_for_verify(card: Any) -> dict[str, Any]:
    """
    Returns a dict to merge into VerifyResult when expiry applies.

    Usage inside verify():
        result = verify_signature(card)
        expiry_result = validate_expiry_for_verify(card)
        if not expiry_result["passed"]:
            return VerifyResult(verified=False, reason=expiry_result["reason"])
    """
    status = check_expiry(card)

    if status == ExpiryStatus.EXPIRED:
        return {
            "passed": False,
            "reason": "card_expired",
            "expires_at": getattr(card, "expires_at", None),
            "status": "expired",
        }

    if status == ExpiryStatus.EXPIRING_SOON:
        remaining = time_remaining(card)
        return {
            "passed": True,
            "reason": None,
            "expires_at": getattr(card, "expires_at", None),
            "status": "expiring_soon",
            "hours_remaining": remaining.total_seconds() / 3600 if remaining else None,
        }

    return {
        "passed": True,
        "reason": None,
        "expires_at": getattr(card, "expires_at", None),
        "status": status.value,
    }
