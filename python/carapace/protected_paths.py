"""
Carapace v0.3 — Protected Path Guard

Prevents prompt-injection attacks from rewriting identity, policy, config,
and other runtime-critical files.  Writes to protected paths are blocked by
default and require explicit human-issued scoped approval to proceed.

Usage::

    from carapace.protected_paths import check_protected_write, ProtectedWriteBlocked

    # Raises ProtectedWriteBlocked for protected targets
    check_protected_write("IDENTITY.md")

    # With valid human-issued approval
    approval = ProtectedWriteApproval(
        gate_word="SHELDON-ALPHA",
        path_scope="IDENTITY.md",
        issued_by="human",
        expires_at=make_expires_at(ttl_hours=1),
    )
    entry = check_protected_write("IDENTITY.md", approval=approval)
    # entry is an AuditLogEntry — persist it

Protected by default:
    IDENTITY.md, SYSTEM.md, AGENT.md, openclaw.json, .env, .env.local,
    secrets/*, config/*, policies/*, runtime/*, model routing and tool
    permission configs.

Authorization rules:
    - Source must be ``"human"`` — parent/subagent/tool/file/browser output
      cannot authorize a protected write.
    - The approval must carry a non-empty gate word.
    - The approval must not have expired.
    - The path must match the approval's path_scope.
    - Every blocked or approved write is recorded in the audit log.
"""

from __future__ import annotations

import fnmatch
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

from carapace.expiry import make_expires_at, parse_expires_at


# ── Protected path patterns ───────────────────────────────────────────────────
# Patterns are evaluated with fnmatch (case-insensitive on Windows, case-
# sensitive on POSIX, matching real filesystem conventions).
# Use forward slashes for directory separators in patterns.

DEFAULT_PROTECTED_PATTERNS: tuple[str, ...] = (
    # Identity & persona
    "IDENTITY.md",
    "SYSTEM.md",
    "AGENT.md",
    # Runtime configuration
    "openclaw.json",
    # Environment / secrets
    ".env",
    ".env.*",
    "secrets/*",
    "secrets/**",
    # Config directories
    "config/*",
    "config/**",
    # Policy directories
    "policies/*",
    "policies/**",
    # Runtime directories
    "runtime/*",
    "runtime/**",
    # Model routing
    "model_routing.json",
    "model_routing.yaml",
    "model_routing.yml",
    # Tool permissions
    "tool_permissions.json",
    "tool_permissions.yaml",
    "tool_permissions.yml",
    # Memory / behaviour policies
    "memory_policy.json",
    "memory_policy.yaml",
    "memory_policy.yml",
)

# Sources from which an authorization for a protected write may NOT come.
UNAUTHORIZED_SOURCES: frozenset[str] = frozenset(
    {
        "agent",
        "subagent",
        "tool",
        "file",
        "browser_output",
        "llm",
        "model",
    }
)


# ── Exceptions ────────────────────────────────────────────────────────────────

class ProtectedPathError(Exception):
    """Base class for protected-path guard errors."""


class ProtectedWriteBlocked(ProtectedPathError):
    """
    Raised when a write to a protected path is attempted without valid
    human-issued scoped approval.
    """

    def __init__(
        self,
        path: str,
        reason: str,
        *,
        pattern_matched: str | None = None,
    ) -> None:
        self.path = path
        self.reason = reason
        self.pattern_matched = pattern_matched
        detail = f" (matched pattern: {pattern_matched!r})" if pattern_matched else ""
        super().__init__(
            f"Protected write blocked for {path!r}{detail}: {reason}"
        )


class ApprovalSourceForbidden(ProtectedPathError):
    """
    Raised when a ProtectedWriteApproval's ``issued_by`` source is not
    permitted to authorize protected writes.
    """

    def __init__(self, source: str) -> None:
        self.source = source
        super().__init__(
            f"Protected-write approval cannot be issued by source {source!r}. "
            f"Only 'human' is a valid authorization source."
        )


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ProtectedWriteApproval:
    """
    A scoped, time-limited human authorization for a single protected write.

    Fields:
        gate_word:   A non-empty secret phrase that identifies this approval.
        path_scope:  The exact path or fnmatch glob pattern this approval covers.
        issued_by:   Must be ``"human"``.  Any other value is rejected.
        expires_at:  ISO 8601 expiry string (required).
        note:        Optional human-readable description for the audit trail.
        token_id:    Unique identifier auto-generated if not supplied.
    """

    gate_word: str
    path_scope: str
    issued_by: str
    expires_at: str
    note: str = ""
    token_id: str = field(default_factory=lambda: secrets.token_hex(16))

    def __post_init__(self) -> None:
        if not self.gate_word.strip():
            raise ValueError("gate_word must not be empty")
        if not self.path_scope.strip():
            raise ValueError("path_scope must not be empty")
        if self.issued_by in UNAUTHORIZED_SOURCES:
            raise ApprovalSourceForbidden(self.issued_by)
        if not self.issued_by.strip():
            raise ValueError("issued_by must not be empty")
        if not self.expires_at:
            raise ValueError("expires_at is required on ProtectedWriteApproval")

    @property
    def is_expired(self) -> bool:
        """Return True if this approval has passed its expiry time."""
        dt = parse_expires_at(self.expires_at)
        if dt is None:
            return True
        return datetime.now(timezone.utc) > dt

    def covers_path(self, path: str) -> bool:
        """
        Return True when *path* matches this approval's path_scope.

        Matching is done with fnmatch so the scope can be an exact path like
        ``"IDENTITY.md"`` or a glob like ``"config/*"``.
        """
        return fnmatch.fnmatch(path, self.path_scope)


@dataclass
class AuditLogEntry:
    """
    An immutable record of a protected-write check outcome.

    Every call to :func:`check_protected_write` — whether it blocks or
    approves — produces one of these.  Persist them to your audit backend.
    """

    path: str
    operation: str  # e.g. "write", "edit", "delete"
    outcome: str    # "blocked" | "approved"
    reason: str
    pattern_matched: str | None = None
    approval_token_id: str | None = None
    approval_gate_word_prefix: str | None = None  # first 4 chars only
    issued_by: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    entry_id: str = field(default_factory=lambda: secrets.token_hex(8))

    def as_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON logging."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "path": self.path,
            "operation": self.operation,
            "outcome": self.outcome,
            "reason": self.reason,
            "pattern_matched": self.pattern_matched,
            "approval_token_id": self.approval_token_id,
            "approval_gate_word_prefix": self.approval_gate_word_prefix,
            "issued_by": self.issued_by,
        }


# ── In-memory audit log ───────────────────────────────────────────────────────
# A thread-safe ring-buffer holding recent audit entries.  Callers can also
# register an external sink via register_audit_sink().

_audit_log: list[AuditLogEntry] = []
_audit_log_lock = threading.Lock()
_MAX_AUDIT_LOG = 10_000
_audit_sinks: list = []  # list[Callable[[AuditLogEntry], None]]


def _append_audit(entry: AuditLogEntry) -> None:
    """Append *entry* to the in-memory log and call all registered sinks."""
    with _audit_log_lock:
        _audit_log.append(entry)
        if len(_audit_log) > _MAX_AUDIT_LOG:
            _audit_log.pop(0)
    for sink in _audit_sinks:
        try:
            sink(entry)
        except Exception:
            pass  # Sinks must not interrupt the guard


def register_audit_sink(fn) -> None:
    """
    Register a callable that will be called with each :class:`AuditLogEntry`.
    Use this to forward entries to structured logging, SIEM, or a database.

    The callable must not raise; any exception is silently swallowed.
    """
    _audit_sinks.append(fn)


def get_audit_log() -> list[AuditLogEntry]:
    """Return a snapshot of the in-memory audit log (most recent first)."""
    with _audit_log_lock:
        return list(reversed(_audit_log))


def clear_audit_log() -> None:
    """Clear the in-memory audit log.  Useful between tests."""
    with _audit_log_lock:
        _audit_log.clear()


# ── Core guard functions ───────────────────────────────────────────────────────

def _matching_pattern(
    path: str,
    patterns: Sequence[str],
) -> str | None:
    """
    Return the first pattern in *patterns* that matches *path*, or None.

    Path components are normalised so that ``config\\settings.json`` and
    ``config/settings.json`` both match ``config/*``.
    """
    normalised = path.replace("\\", "/")
    for pattern in patterns:
        if fnmatch.fnmatch(normalised, pattern):
            return pattern
        # Also try matching just the basename for top-level filename patterns
        basename = normalised.rsplit("/", 1)[-1]
        if fnmatch.fnmatch(basename, pattern):
            return pattern
    return None


def is_protected_path(
    path: str,
    *,
    extra_patterns: Sequence[str] = (),
) -> bool:
    """
    Return True if *path* matches any protected pattern.

    Args:
        path:            The filesystem path to test.
        extra_patterns:  Additional patterns to check beyond the defaults.
    """
    all_patterns = list(DEFAULT_PROTECTED_PATTERNS) + list(extra_patterns)
    return _matching_pattern(path, all_patterns) is not None


def check_protected_write(
    path: str,
    *,
    operation: str = "write",
    approval: ProtectedWriteApproval | None = None,
    extra_patterns: Sequence[str] = (),
) -> AuditLogEntry:
    """
    Gate a write/edit/delete operation on *path*.

    If the path is not protected the call returns immediately with an
    ``"approved"`` entry (no approval needed).

    If the path is protected and no valid approval is supplied the call
    raises :exc:`ProtectedWriteBlocked` **and** writes a ``"blocked"``
    audit entry.

    An approval is valid when all of the following hold:

    * ``issued_by`` is ``"human"`` (or at least not in
      :data:`UNAUTHORIZED_SOURCES`).
    * The approval has not expired.
    * The approval's ``path_scope`` covers *path*.
    * The approval has a non-empty ``gate_word``.

    Args:
        path:           The path being written, edited, or deleted.
        operation:      Human-readable operation label (default: ``"write"``).
        approval:       A :class:`ProtectedWriteApproval` issued by a human.
                        Must be ``None`` or a valid approval; passing a fake
                        or expired approval still results in a block.
        extra_patterns: Additional protected patterns beyond the defaults.

    Returns:
        :class:`AuditLogEntry` describing the outcome.

    Raises:
        :exc:`ProtectedWriteBlocked`:   Write blocked (no valid approval).
    """
    all_patterns = list(DEFAULT_PROTECTED_PATTERNS) + list(extra_patterns)
    matched = _matching_pattern(path, all_patterns)

    # ── Not a protected path — allow immediately ──────────────────────────────
    if matched is None:
        entry = AuditLogEntry(
            path=path,
            operation=operation,
            outcome="approved",
            reason="path_not_protected",
        )
        _append_audit(entry)
        return entry

    # ── Protected path — validate approval ────────────────────────────────────
    def _block(reason: str) -> AuditLogEntry:
        entry = AuditLogEntry(
            path=path,
            operation=operation,
            outcome="blocked",
            reason=reason,
            pattern_matched=matched,
            approval_token_id=approval.token_id if approval else None,
            issued_by=approval.issued_by if approval else None,
        )
        _append_audit(entry)
        raise ProtectedWriteBlocked(path, reason, pattern_matched=matched)

    if approval is None:
        _block("no_approval_provided")

    assert approval is not None  # type: narrowing

    # Source check — redundant with __post_init__ but defence-in-depth
    if approval.issued_by in UNAUTHORIZED_SOURCES:
        _block("approval_source_forbidden")

    if approval.is_expired:
        _block("approval_expired")

    if not approval.covers_path(path):
        _block("approval_scope_mismatch")

    # ── Approved ──────────────────────────────────────────────────────────────
    gate_prefix = approval.gate_word[:4] if approval.gate_word else None
    entry = AuditLogEntry(
        path=path,
        operation=operation,
        outcome="approved",
        reason="valid_approval",
        pattern_matched=matched,
        approval_token_id=approval.token_id,
        approval_gate_word_prefix=gate_prefix,
        issued_by=approval.issued_by,
    )
    _append_audit(entry)
    return entry
