"""
Carapace v0.4 — Epistemic Tracking

Tamper-evident, append-only provenance log for agent decisions.
When an agent makes a decision based on information from another agent,
it logs that provenance. The whole chain becomes cryptographically verifiable.

This is the digital equivalent of the paper trail in a PSM incident
investigation. It's the feature that gets Carapace taken seriously in
regulated industries — HIPAA, FDA 21 CFR Part 11, NERC CIP.

Usage:
    # Create a provenance log for an agent
    log = EpistemicLog(agent_id="my-agent-uuid")

    # Log a decision with provenance
    entry = log.record(
        action="classified_invoice",
        sources=[
            Source(agent_id="ocr-agent", card_signature="hex...", data_hash="sha256..."),
            Source(agent_id="policy-agent", card_signature="hex...", data_hash="sha256..."),
        ],
        confidence=0.92,
        reasoning="Matched vendor name against approved vendor list",
    )

    # Verify log integrity (hash chain)
    assert log.verify_integrity()

    # Export for audit
    audit = log.export_audit_trail()
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Sequence


# ── Types ─────────────────────────────────────────────────────────────────────

class ConfidenceLevel(Enum):
    """Standardized confidence tiers for epistemic metadata."""
    VERIFIED = "verified"           # Cryptographically verified source
    HIGH = "high"                   # Multiple corroborating sources
    MEDIUM = "medium"               # Single authoritative source
    LOW = "low"                     # Inferred or derived
    UNVERIFIED = "unverified"       # No source verification performed
    HUMAN_OVERRIDE = "human_override"  # Human operator made this call


@dataclass
class Source:
    """A provenance source — another agent or data origin that informed a decision."""
    agent_id: str                          # Source agent's Carapace ID
    card_signature: str | None = None      # Ed25519 sig of the source's card at decision time
    data_hash: str | None = None           # SHA-256 of the specific data received
    timestamp: str | None = None           # When data was received (ISO 8601)
    description: str | None = None         # Human-readable description of what was received

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "card_signature": self.card_signature,
            "data_hash": self.data_hash,
            "timestamp": self.timestamp or datetime.now(timezone.utc).isoformat(),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Source:
        return cls(
            agent_id=data["agent_id"],
            card_signature=data.get("card_signature"),
            data_hash=data.get("data_hash"),
            timestamp=data.get("timestamp"),
            description=data.get("description"),
        )


@dataclass
class EpistemicEntry:
    """A single entry in the epistemic provenance log."""
    sequence: int                          # Monotonic sequence number
    agent_id: str                          # Agent that made the decision
    action: str                            # What was decided/done
    sources: list[Source]                  # What informed the decision
    confidence: float                      # 0.0–1.0
    confidence_level: ConfidenceLevel      # Categorical tier
    reasoning: str | None                  # Why this decision was made
    timestamp: str                         # When (ISO 8601)
    data_hash: str                         # SHA-256 of the entry's content (excl. chain fields)
    prev_hash: str                         # Hash of the previous entry (chain link)
    entry_hash: str                        # SHA-256 of (data_hash + prev_hash) — the chain
    delegation_id: str | None = None       # If acting under delegation, which one
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "agent_id": self.agent_id,
            "action": self.action,
            "sources": [s.to_dict() for s in self.sources],
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "reasoning": self.reasoning,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "delegation_id": self.delegation_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EpistemicEntry:
        return cls(
            sequence=data["sequence"],
            agent_id=data["agent_id"],
            action=data["action"],
            sources=[Source.from_dict(s) for s in data.get("sources", [])],
            confidence=data["confidence"],
            confidence_level=ConfidenceLevel(data["confidence_level"]),
            reasoning=data.get("reasoning"),
            timestamp=data["timestamp"],
            data_hash=data["data_hash"],
            prev_hash=data["prev_hash"],
            entry_hash=data["entry_hash"],
            delegation_id=data.get("delegation_id"),
            metadata=data.get("metadata", {}),
        )


# ── Hashing ───────────────────────────────────────────────────────────────────

def _hash_content(content: str) -> str:
    """SHA-256 hash of content, returned as hex."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _compute_data_hash(
    agent_id: str,
    action: str,
    sources: list[Source],
    confidence: float,
    reasoning: str | None,
    timestamp: str,
    delegation_id: str | None,
) -> str:
    """Hash the decision content (everything except chain fields)."""
    payload = json.dumps({
        "agent_id": agent_id,
        "action": action,
        "sources": [s.to_dict() for s in sources],
        "confidence": confidence,
        "reasoning": reasoning,
        "timestamp": timestamp,
        "delegation_id": delegation_id,
    }, sort_keys=True, separators=(",", ":"))
    return _hash_content(payload)


def _compute_entry_hash(data_hash: str, prev_hash: str) -> str:
    """Hash chain link: SHA-256(data_hash + prev_hash)."""
    return _hash_content(data_hash + prev_hash)


def _confidence_to_level(confidence: float) -> ConfidenceLevel:
    """Map a numeric confidence to a categorical level."""
    if confidence >= 0.95:
        return ConfidenceLevel.VERIFIED
    elif confidence >= 0.8:
        return ConfidenceLevel.HIGH
    elif confidence >= 0.6:
        return ConfidenceLevel.MEDIUM
    elif confidence >= 0.3:
        return ConfidenceLevel.LOW
    else:
        return ConfidenceLevel.UNVERIFIED


# ── Genesis Hash ──────────────────────────────────────────────────────────────

GENESIS_HASH = _hash_content("carapace:epistemic:genesis:v0.4")


# ── Epistemic Log ─────────────────────────────────────────────────────────────

class EpistemicLog:
    """
    Append-only, tamper-evident provenance log for a single agent.

    Each entry is hash-chained to the previous entry. Tampering with
    any entry invalidates all subsequent hashes.

    This is NOT stored in ARIA (privacy concern) — it's a local ledger
    that the agent operator maintains. The SDK provides the structure;
    storage is the operator's responsibility.
    """

    def __init__(self, agent_id: str, entries: list[EpistemicEntry] | None = None):
        self.agent_id = agent_id
        self._entries: list[EpistemicEntry] = entries or []

    @property
    def entries(self) -> list[EpistemicEntry]:
        return list(self._entries)

    @property
    def length(self) -> int:
        return len(self._entries)

    @property
    def latest_hash(self) -> str:
        """Hash of the most recent entry, or genesis hash if empty."""
        if not self._entries:
            return GENESIS_HASH
        return self._entries[-1].entry_hash

    def record(
        self,
        action: str,
        sources: list[Source] | None = None,
        confidence: float = 0.5,
        confidence_level: ConfidenceLevel | None = None,
        reasoning: str | None = None,
        delegation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> EpistemicEntry:
        """
        Record a decision with full provenance.

        Args:
            action: What was decided or done.
            sources: What informed the decision (other agents, data).
            confidence: Numeric confidence 0.0–1.0.
            confidence_level: Override the auto-mapped level.
            reasoning: Human-readable explanation.
            delegation_id: If acting under delegation.
            metadata: Arbitrary key-value pairs.
            timestamp: Override timestamp (for testing).

        Returns:
            The new EpistemicEntry (already appended to the log).
        """
        sources = sources or []
        ts = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        level = confidence_level or _confidence_to_level(confidence)

        sequence = len(self._entries) + 1
        prev_hash = self.latest_hash

        data_hash = _compute_data_hash(
            agent_id=self.agent_id,
            action=action,
            sources=sources,
            confidence=confidence,
            reasoning=reasoning,
            timestamp=ts,
            delegation_id=delegation_id,
        )

        entry_hash = _compute_entry_hash(data_hash, prev_hash)

        entry = EpistemicEntry(
            sequence=sequence,
            agent_id=self.agent_id,
            action=action,
            sources=sources,
            confidence=confidence,
            confidence_level=level,
            reasoning=reasoning,
            timestamp=ts,
            data_hash=data_hash,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            delegation_id=delegation_id,
            metadata=metadata or {},
        )

        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> tuple[bool, int | None]:
        """
        Verify the hash chain is intact.

        Returns:
            (True, None) if valid.
            (False, sequence_number) if broken at that entry.
        """
        if not self._entries:
            return (True, None)

        # First entry must chain from genesis
        expected_prev = GENESIS_HASH
        for entry in self._entries:
            if entry.prev_hash != expected_prev:
                return (False, entry.sequence)

            # Recompute data hash
            recomputed_data = _compute_data_hash(
                agent_id=entry.agent_id,
                action=entry.action,
                sources=entry.sources,
                confidence=entry.confidence,
                reasoning=entry.reasoning,
                timestamp=entry.timestamp,
                delegation_id=entry.delegation_id,
            )
            if recomputed_data != entry.data_hash:
                return (False, entry.sequence)

            # Recompute chain hash
            recomputed_entry = _compute_entry_hash(entry.data_hash, entry.prev_hash)
            if recomputed_entry != entry.entry_hash:
                return (False, entry.sequence)

            expected_prev = entry.entry_hash

        return (True, None)

    def export_audit_trail(self) -> dict[str, Any]:
        """
        Export the full log for audit purposes.
        Includes integrity verification result.
        """
        valid, broken_at = self.verify_integrity()
        return {
            "agent_id": self.agent_id,
            "entry_count": self.length,
            "integrity_valid": valid,
            "broken_at_sequence": broken_at,
            "genesis_hash": GENESIS_HASH,
            "latest_hash": self.latest_hash,
            "entries": [e.to_dict() for e in self._entries],
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

    def export_json(self) -> str:
        """Serialize the full log to JSON."""
        return json.dumps(self.export_audit_trail(), indent=2)

    @classmethod
    def from_json(cls, data: str | dict) -> EpistemicLog:
        """Reconstruct a log from exported JSON."""
        if isinstance(data, str):
            data = json.loads(data)
        entries = [EpistemicEntry.from_dict(e) for e in data.get("entries", [])]
        return cls(agent_id=data["agent_id"], entries=entries)

    def query(
        self,
        action: str | None = None,
        source_agent_id: str | None = None,
        min_confidence: float | None = None,
        delegation_id: str | None = None,
    ) -> list[EpistemicEntry]:
        """Query entries by filter criteria."""
        results = self._entries

        if action:
            results = [e for e in results if e.action == action]

        if source_agent_id:
            results = [
                e for e in results
                if any(s.agent_id == source_agent_id for s in e.sources)
            ]

        if min_confidence is not None:
            results = [e for e in results if e.confidence >= min_confidence]

        if delegation_id:
            results = [e for e in results if e.delegation_id == delegation_id]

        return results


# ── Data Hashing Utility ──────────────────────────────────────────────────────

def hash_data(data: str | bytes) -> str:
    """
    SHA-256 hash for creating data_hash values in Source objects.

    Usage:
        source = Source(
            agent_id="ocr-agent",
            data_hash=hash_data(ocr_output_text),
        )
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
