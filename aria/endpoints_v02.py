"""
ARIA v0.2 FastAPI endpoints.

Implements:
- POST   /aria/v1/agents           — register an agent card (with expires_at / versioning)
- GET    /aria/v1/agents/{id}      — fetch a card
- GET    /aria/v1/agents/{id}/verify  — verify a card (expiry + supersedes checks)
- GET    /aria/v1/agents/{id}/history — version chain for an agent lineage
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from carapace.expiry import validate_expiry_for_verify
from carapace.versioning import (
    VersionEntry,
    validate_version_chain,
    validate_supersedes_registration,
    OwnerMismatchError,
)

router = APIRouter(prefix="/aria/v1")


# ── Pydantic models ───────────────────────────────────────────────────────────

class Capability(BaseModel):
    id: str
    name: str
    description: str = ""


class Endpoint(BaseModel):
    protocol: str
    url: str


class AgentRegistration(BaseModel):
    name: str
    description: str = ""
    framework: str = ""
    capabilities: list[Capability] = []
    endpoints: list[Endpoint] = []
    version: str | None = None          # semver (v0.1 field)
    tags: list[str] = []
    metadata: dict = {}
    owner_public_key: str               # hex Ed25519 public key
    signature: str                      # Ed25519 hex signature over JCS payload

    # v0.2 additions
    expires_at: str | None = None       # ISO 8601, nullable
    card_version: int = Field(default=1, ge=1)
    supersedes: str | None = None       # UUID of predecessor card


class VerifyResponse(BaseModel):
    verified: bool
    reason: str | None = None
    agent: dict | None = None
    expiry_status: str | None = None
    hours_remaining: float | None = None
    expired: bool = False
    successor: str | None = None


class VersionHistoryResponse(BaseModel):
    agent_id: str
    lineage_length: int
    current: dict | None
    original: dict | None
    history: list[dict]


# ── Dependency stub — replace with real DB layer ──────────────────────────────

class Database:
    """Stub database layer. Replace with real async DB client."""

    async def get_agent(self, agent_id: str) -> dict | None:
        raise NotImplementedError("Wire up real DB")

    async def create_agent(self, data: dict) -> dict:
        raise NotImplementedError("Wire up real DB")

    async def update_agent_status(
        self,
        agent_id: str,
        status: str,
        superseded_by: str | None = None,
    ) -> None:
        raise NotImplementedError("Wire up real DB")


def get_db() -> Database:
    return Database()


# ── Registration ──────────────────────────────────────────────────────────────

@router.post("/agents", status_code=201)
async def register_agent(
    req: AgentRegistration,
    db: Database = Depends(get_db),
) -> dict:
    """
    Register an agent card. Supports v0.2 fields:
    - expires_at: optional card TTL
    - card_version / supersedes: version chaining
    """
    if req.supersedes:
        old_card = await db.get_agent(req.supersedes)
        if not old_card:
            raise HTTPException(404, f"Superseded card {req.supersedes} not found")

        try:
            validate_supersedes_registration(
                new_owner_key=req.owner_public_key,
                superseded_card=old_card,
            )
        except OwnerMismatchError as e:
            raise HTTPException(403, str(e))

    card_data: dict[str, Any] = {
        "name": req.name,
        "description": req.description,
        "framework": req.framework,
        "capabilities": [c.model_dump() for c in req.capabilities],
        "endpoints": [e.model_dump() for e in req.endpoints],
        "version": req.version,
        "tags": req.tags,
        "metadata": req.metadata,
        "owner": {"public_key": req.owner_public_key},
        "signature": req.signature,
        "status": "active",
        # v0.2 fields
        "expires_at": req.expires_at,
        "card_version": req.card_version,
        "supersedes": req.supersedes,
        "superseded_by": None,
    }

    new_card = await db.create_agent(card_data)

    if req.supersedes:
        await db.update_agent_status(
            req.supersedes,
            "superseded",
            superseded_by=new_card["id"],
        )

    return new_card


# ── Fetch ─────────────────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}")
async def get_agent(
    agent_id: str,
    db: Database = Depends(get_db),
) -> dict:
    card = await db.get_agent(agent_id)
    if not card:
        raise HTTPException(404, f"Agent {agent_id} not found")
    return card


# ── Verify ────────────────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/verify")
async def verify_agent(
    agent_id: str,
    db: Database = Depends(get_db),
) -> VerifyResponse:
    """
    Verify an agent card. Checks:
    1. Card exists
    2. Card status (revoked / superseded)
    3. Expiry (via carapace.expiry.validate_expiry_for_verify)
    """
    card = await db.get_agent(agent_id)
    if not card:
        raise HTTPException(404, f"Agent {agent_id} not found")

    # Check superseded
    if card.get("status") == "superseded":
        return VerifyResponse(
            verified=False,
            reason="card_superseded",
            successor=card.get("superseded_by"),
        )

    # Check revoked
    if card.get("status") == "revoked":
        return VerifyResponse(verified=False, reason="card_revoked")

    # Check expiry
    expiry_result = validate_expiry_for_verify(card)
    if not expiry_result["passed"]:
        return VerifyResponse(
            verified=False,
            reason=expiry_result["reason"],
            expired=True,
            expiry_status=expiry_result.get("status"),
        )

    return VerifyResponse(
        verified=True,
        agent=card,
        expiry_status=expiry_result.get("status"),
        hours_remaining=expiry_result.get("hours_remaining"),
    )


# ── Version history ───────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/history")
async def get_version_history(
    agent_id: str,
    db: Database = Depends(get_db),
) -> VersionHistoryResponse:
    """
    Return the full supersedes chain for an agent lineage.
    Walks backward (via supersedes) and forward (via superseded_by).
    """
    card = await db.get_agent(agent_id)
    if not card:
        raise HTTPException(404, f"Agent {agent_id} not found")

    chain: list[dict] = [card]

    # Walk backward
    current = card
    while current.get("supersedes"):
        predecessor = await db.get_agent(current["supersedes"])
        if not predecessor:
            break
        chain.insert(0, predecessor)
        current = predecessor

    # Walk forward
    current = card
    while current.get("superseded_by"):
        successor_card = await db.get_agent(current["superseded_by"])
        if not successor_card:
            break
        chain.append(successor_card)
        current = successor_card

    validated = validate_version_chain(chain)

    def entry_to_dict(e: VersionEntry) -> dict:
        return {
            "card_id": e.card_id,
            "version": e.version,
            "status": e.status,
            "supersedes": e.supersedes,
            "superseded_by": e.superseded_by,
            "created_at": e.created_at,
        }

    current_entry = validated.current
    original_entry = validated.original

    return VersionHistoryResponse(
        agent_id=agent_id,
        lineage_length=validated.length,
        current=entry_to_dict(current_entry) if current_entry else None,
        original=entry_to_dict(original_entry) if original_entry else None,
        history=[entry_to_dict(e) for e in validated.entries],
    )
