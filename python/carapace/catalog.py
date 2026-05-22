"""
Carapace SDK v0.5.0 — Catalog Sync

ETag-based catalog fetch and local query helpers. The catalog is the single
source of truth for which tools ARIA knows about. Agents should refresh it
every 5 minutes; on ARIA unreachable, fail-open with the stale catalog.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class CatalogEntry:
    """One tool from the ARIA catalog."""
    id: str
    name: str
    description: str
    endpoint_url: str
    status: str                         # active | suspended | pending
    clawmark_score: float               # Clawmark aggregate, 0-5 scale (0 = unscored)
    gate_pass: bool                     # aggregate >= 3.0
    tier: str
    safety_class: str
    certification_tier: str
    streaming_supported: bool
    clawmark_breakdown: dict[str, Any] = field(default_factory=dict)
    scope_requirements: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CatalogEntry":
        # ARIA sends clawmark_score=null for unscored tools — treat as 0.0.
        raw_score = d.get("clawmark_score")
        return cls(
            id=d["id"],
            name=d["name"],
            description=d.get("description", ""),
            endpoint_url=d["endpoint_url"],
            status=d["status"],
            clawmark_score=float(raw_score) if raw_score is not None else 0.0,
            gate_pass=bool(d.get("gate_pass", False)),
            tier=d.get("tier", "free"),
            safety_class=d.get("safety_class", "safe"),
            certification_tier=d.get("certification_tier", ""),
            streaming_supported=bool(d.get("streaming_supported", False)),
            clawmark_breakdown=d.get("clawmark_breakdown", {}),
            scope_requirements=d.get("scope_requirements", {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "endpoint_url": self.endpoint_url,
            "status": self.status,
            "clawmark_score": self.clawmark_score,
            "gate_pass": self.gate_pass,
            "tier": self.tier,
            "safety_class": self.safety_class,
            "certification_tier": self.certification_tier,
            "streaming_supported": self.streaming_supported,
            "clawmark_breakdown": self.clawmark_breakdown,
            "scope_requirements": self.scope_requirements,
        }


@dataclass
class CatalogState:
    """Snapshot of the full ARIA tool catalog."""
    catalog: list[CatalogEntry]
    total: int
    etag: str
    fetched_at: str

    def get(self, tool_id: str) -> Optional[CatalogEntry]:
        for entry in self.catalog:
            if entry.id == tool_id:
                return entry
        return None

    def is_known(self, tool_id: str) -> bool:
        return self.get(tool_id) is not None

    def is_active(self, tool_id: str) -> bool:
        entry = self.get(tool_id)
        return entry is not None and entry.status == "active"

    def gate_pass(self, tool_id: str) -> bool:
        entry = self.get(tool_id)
        return entry is not None and entry.gate_pass

    def active_tools(self) -> list[CatalogEntry]:
        return [e for e in self.catalog if e.status == "active"]


@dataclass
class GateResult:
    """
    Result of a five-gate pre-call verification check.

    Gates:
      1. catalog_membership  — tool is in the ARIA catalog
      2. active_status       — tool is not suspended
      3. revocation_clear    — tool is not currently revoked
      4. clawmark_gate       — Clawmark aggregate >= threshold (default 3.0, 0-5 scale)
      5. delegation_valid    — if delegated, delegation is valid and not expired
    """
    passed: bool
    tool_id: str
    gates_checked: list[str] = field(default_factory=list)
    gates_failed: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked_by(self) -> Optional[str]:
        return self.gates_failed[0] if self.gates_failed else None


def fetch_catalog(
    aria_url: str,
    etag: Optional[str] = None,
    timeout: float = 5.0,
) -> tuple[Optional[CatalogState], Optional[str]]:
    """
    Fetch the ARIA catalog with ETag support.

    Returns:
        (CatalogState, new_etag) — catalog changed, use it
        (None, existing_etag)   — 304 Not Modified, nothing changed

    Raises httpx.HTTPError, httpx.TimeoutException on network failure.
    The caller MUST handle these and fail-open (use stale catalog + log).
    """
    try:
        import httpx
    except ImportError as exc:
        raise ImportError("httpx is required for catalog sync: pip install httpx") from exc

    headers: dict[str, str] = {}
    if etag:
        headers["If-None-Match"] = etag

    resp = httpx.get(
        f"{aria_url.rstrip('/')}/aria/v1/catalog",
        headers=headers,
        timeout=timeout,
    )

    if resp.status_code == 304:
        return None, etag

    resp.raise_for_status()
    data = resp.json()

    new_etag = resp.headers.get("etag", "").strip('"') or data.get("etag") or ""
    entries = [CatalogEntry.from_dict(t) for t in data.get("catalog", [])]
    state = CatalogState(
        catalog=entries,
        total=data.get("total", len(entries)),
        etag=new_etag,
        fetched_at=datetime.now(timezone.utc).isoformat(),
    )
    return state, new_etag


def run_gate_check(
    tool_id: str,
    catalog: Optional[CatalogState],
    *,
    revoked_ids: Optional[set[str]] = None,
    score_threshold: float = 3.0,
    delegation_valid: Optional[bool] = None,
    trust_gates_enabled: bool = True,
) -> GateResult:
    """
    Run five-gate pre-call verification against a local catalog snapshot.

    When trust_gates_enabled=False, all gates pass (observe-only mode).
    When catalog is None (ARIA unreachable), fail-open — all gates pass with a warning.
    """
    if not trust_gates_enabled:
        return GateResult(
            passed=True,
            tool_id=tool_id,
            gates_checked=[],
            gates_failed=[],
            details={"mode": "observe_only"},
        )

    if catalog is None:
        return GateResult(
            passed=True,
            tool_id=tool_id,
            gates_checked=[],
            gates_failed=[],
            details={"mode": "fail_open", "reason": "aria_unreachable"},
        )

    gates_checked: list[str] = []
    gates_failed: list[str] = []
    details: dict[str, Any] = {}

    # Gate 1 — catalog membership
    gates_checked.append("catalog_membership")
    entry = catalog.get(tool_id)
    if entry is None:
        gates_failed.append("catalog_membership")
        details["catalog_membership"] = "tool not in catalog"
        return GateResult(passed=False, tool_id=tool_id, gates_checked=gates_checked, gates_failed=gates_failed, details=details)

    # Gate 2 — active status
    gates_checked.append("active_status")
    if entry.status != "active":
        gates_failed.append("active_status")
        details["active_status"] = f"status={entry.status}"
        return GateResult(passed=False, tool_id=tool_id, gates_checked=gates_checked, gates_failed=gates_failed, details=details)

    # Gate 3 — revocation clear
    gates_checked.append("revocation_clear")
    if revoked_ids and tool_id in revoked_ids:
        gates_failed.append("revocation_clear")
        details["revocation_clear"] = "tool is in active revocation set"
        return GateResult(passed=False, tool_id=tool_id, gates_checked=gates_checked, gates_failed=gates_failed, details=details)

    # Gate 4 — Clawmark score
    gates_checked.append("clawmark_gate")
    if entry.clawmark_score < score_threshold:
        gates_failed.append("clawmark_gate")
        details["clawmark_gate"] = f"score={entry.clawmark_score} < threshold={score_threshold}"
        return GateResult(passed=False, tool_id=tool_id, gates_checked=gates_checked, gates_failed=gates_failed, details=details)

    # Gate 5 — delegation validity (only checked when a delegation is involved)
    if delegation_valid is not None:
        gates_checked.append("delegation_valid")
        if not delegation_valid:
            gates_failed.append("delegation_valid")
            details["delegation_valid"] = "delegation token is expired or revoked"
            return GateResult(passed=False, tool_id=tool_id, gates_checked=gates_checked, gates_failed=gates_failed, details=details)

    details["score"] = entry.clawmark_score
    return GateResult(passed=True, tool_id=tool_id, gates_checked=gates_checked, gates_failed=gates_failed, details=details)
