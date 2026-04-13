"""
Carapace v0.2 — Agent Card Versioning

Provides traceable capability evolution via version chains.
When you update an agent's capabilities, the new card cryptographically
references the old one. Auditors see a chain, not cards appearing from nowhere.

Usage:
    # Register a new version of an existing card
    new_card = client.register(
        name="ResearchAgent",
        capabilities=[...updated...],
        version=2,
        supersedes="uuid-of-v1-card",
    )

    # Query version history
    history = client.get_version_history(agent_id)

    # Validate a supersedes chain
    chain = validate_version_chain(cards)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence


# ── Exceptions ────────────────────────────────────────────────────────────────

class VersionChainError(Exception):
    """Raised when a version chain is broken or invalid."""
    pass


class OwnerMismatchError(VersionChainError):
    """Superseding card has a different owner than the original."""
    pass


class VersionSequenceError(VersionChainError):
    """Version numbers are not monotonically increasing."""
    pass


class SupersedesNotFoundError(VersionChainError):
    """The card referenced by supersedes doesn't exist."""
    pass


# ── Version Chain Dataclass ───────────────────────────────────────────────────

@dataclass
class VersionEntry:
    """A single entry in a version chain."""
    card_id: str
    version: int
    supersedes: str | None
    superseded_by: str | None
    owner_public_key: str
    created_at: str | None = None
    status: str = "active"  # active, superseded, revoked, expired

    @classmethod
    def from_card(cls, card: Any) -> VersionEntry:
        """Build from an AgentCard or dict."""
        if isinstance(card, dict):
            owner_key = card.get("owner", {}).get("public_key", "")
            return cls(
                card_id=card.get("id", ""),
                version=card.get("version", 1),
                supersedes=card.get("supersedes"),
                superseded_by=card.get("superseded_by"),
                owner_public_key=owner_key,
                created_at=card.get("created_at"),
                status=card.get("status", "active"),
            )
        # Object form
        owner = getattr(card, "owner", None)
        owner_key = (
            getattr(owner, "public_key", "")
            if owner else ""
        )
        return cls(
            card_id=getattr(card, "id", ""),
            version=getattr(card, "version", 1),
            supersedes=getattr(card, "supersedes", None),
            superseded_by=getattr(card, "superseded_by", None),
            owner_public_key=owner_key,
            created_at=getattr(card, "created_at", None),
            status=getattr(card, "status", "active"),
        )


@dataclass
class VersionChain:
    """Ordered version history for an agent lineage."""
    entries: list[VersionEntry] = field(default_factory=list)

    @property
    def current(self) -> VersionEntry | None:
        """The latest (highest version) entry."""
        if not self.entries:
            return None
        return max(self.entries, key=lambda e: e.version)

    @property
    def original(self) -> VersionEntry | None:
        """The first (v1) entry."""
        if not self.entries:
            return None
        return min(self.entries, key=lambda e: e.version)

    @property
    def length(self) -> int:
        return len(self.entries)

    def is_valid(self) -> bool:
        """Check if the chain is internally consistent."""
        try:
            validate_version_chain(self.entries)
            return True
        except VersionChainError:
            return False

    def capabilities_diff(self, from_version: int, to_version: int) -> dict:
        """
        Show capability changes between two versions.
        Returns { added: [...], removed: [...], unchanged: [...] }
        """
        from_entry = next((e for e in self.entries if e.version == from_version), None)
        to_entry = next((e for e in self.entries if e.version == to_version), None)
        if not from_entry or not to_entry:
            raise ValueError(f"Version {from_version} or {to_version} not found in chain")
        # Note: actual capability data would need to come from the full cards,
        # not just the VersionEntry. This is a placeholder for the diff logic
        # that the full implementation would wire up with card data.
        return {
            "from_version": from_version,
            "to_version": to_version,
            "from_card_id": from_entry.card_id,
            "to_card_id": to_entry.card_id,
        }


# ── Validation ────────────────────────────────────────────────────────────────

def validate_version_chain(
    entries: Sequence[VersionEntry | dict | Any],
) -> VersionChain:
    """
    Validate that a sequence of cards/entries forms a valid version chain.

    Checks:
    1. All entries have the same owner public key
    2. Version numbers are monotonically increasing (no gaps required)
    3. Each supersedes reference points to the previous version
    4. Exactly one entry has supersedes=None (the original)

    Raises VersionChainError subclasses on failure.
    Returns a validated VersionChain on success.
    """
    # Normalize to VersionEntry
    normalized: list[VersionEntry] = []
    for e in entries:
        if isinstance(e, VersionEntry):
            normalized.append(e)
        else:
            normalized.append(VersionEntry.from_card(e))

    if not normalized:
        return VersionChain(entries=[])

    # Sort by version
    normalized.sort(key=lambda e: e.version)

    # Check single owner
    owners = set(e.owner_public_key for e in normalized)
    if len(owners) > 1:
        raise OwnerMismatchError(
            f"Version chain contains multiple owners: {owners}. "
            "All versions must share the same owner key."
        )

    # Check version sequence
    for i, entry in enumerate(normalized):
        if entry.version < 1:
            raise VersionSequenceError(
                f"Version must be >= 1, got {entry.version} for card {entry.card_id}"
            )
        if i > 0 and entry.version <= normalized[i - 1].version:
            raise VersionSequenceError(
                f"Version {entry.version} is not greater than previous "
                f"version {normalized[i - 1].version}"
            )

    # Check supersedes chain
    originals = [e for e in normalized if e.supersedes is None]
    if len(originals) != 1:
        raise VersionChainError(
            f"Expected exactly one original (supersedes=None), found {len(originals)}"
        )
    if originals[0] != normalized[0]:
        raise VersionChainError(
            "The original card (supersedes=None) must be the lowest version"
        )

    # Each subsequent entry should supersede the previous
    card_id_set = {e.card_id for e in normalized}
    for i in range(1, len(normalized)):
        expected_predecessor = normalized[i - 1].card_id
        actual = normalized[i].supersedes
        if actual != expected_predecessor:
            # Not a hard error — sparse chains are possible in practice
            # (e.g., if intermediate versions were revoked and cleaned up).
            # But the supersedes target must exist in the chain.
            if actual not in card_id_set:
                raise SupersedesNotFoundError(
                    f"Card {normalized[i].card_id} (v{normalized[i].version}) "
                    f"supersedes {actual}, which is not in the chain"
                )

    return VersionChain(entries=normalized)


# ── Registration Helpers ──────────────────────────────────────────────────────

def prepare_version_fields(
    supersedes_card: Any | None = None,
) -> dict[str, Any]:
    """
    Prepare version and supersedes fields for a registration call.

    Usage:
        # First registration (no predecessor)
        fields = prepare_version_fields()
        # -> {"version": 1, "supersedes": None}

        # Update an existing agent
        fields = prepare_version_fields(supersedes_card=old_card)
        # -> {"version": 2, "supersedes": "old-uuid"}
    """
    if supersedes_card is None:
        return {"version": 1, "supersedes": None}

    old_version = (
        supersedes_card.get("version", 1) if isinstance(supersedes_card, dict)
        else getattr(supersedes_card, "version", 1)
    )
    old_id = (
        supersedes_card.get("id") if isinstance(supersedes_card, dict)
        else getattr(supersedes_card, "id", None)
    )

    return {
        "version": old_version + 1,
        "supersedes": old_id,
    }


def validate_supersedes_registration(
    new_owner_key: str,
    superseded_card: Any,
) -> None:
    """
    Pre-registration check: verify the new card's owner matches the
    superseded card. Called by ARIA before accepting a versioned registration.

    Raises OwnerMismatchError if keys don't match.
    """
    if isinstance(superseded_card, dict):
        old_key = superseded_card.get("owner", {}).get("public_key", "")
    else:
        owner = getattr(superseded_card, "owner", None)
        old_key = getattr(owner, "public_key", "") if owner else ""

    if new_owner_key != old_key:
        raise OwnerMismatchError(
            f"Cannot supersede card owned by {old_key[:16]}... "
            f"with key {new_owner_key[:16]}... — owner must match"
        )
