"""
ARIA v0.3 FastAPI endpoints — Delegation Chain Support.

Implements:
- POST /aria/v1/delegations                    — store a signed delegation token
- GET  /aria/v1/delegations/{id}/verify        — verify a delegation chain
- GET  /aria/v1/agents/{id}/delegations        — list delegations granted/received
- POST /aria/v1/delegations/{id}/revoke        — explicit revocation with cascade
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from carapace.delegation import (
    DelegationToken,
    verify_delegation,
    verify_delegation_chain,
    validate_capability_subset,
    CapabilityEscalation,
)

router = APIRouter(prefix="/aria/v1")


# ── Pydantic models ───────────────────────────────────────────────────────────

class DelegationCreateRequest(BaseModel):
    delegator_card_id: str
    delegator_public_key: str
    delegate_card_id: str
    delegated_capabilities: list[str]
    expires_at: str
    parent_delegation_id: str | None = None
    max_redelegation_depth: int = Field(default=2, ge=0)
    task_context: str | None = None
    nonce: str
    signature: str

    def to_delegation_token(self) -> DelegationToken:
        from datetime import datetime, timezone
        return DelegationToken(
            id="",  # not yet assigned
            delegator_card_id=self.delegator_card_id,
            delegator_public_key=self.delegator_public_key,
            delegate_card_id=self.delegate_card_id,
            delegated_capabilities=sorted(self.delegated_capabilities),
            expires_at=self.expires_at,
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            parent_delegation_id=self.parent_delegation_id,
            max_redelegation_depth=self.max_redelegation_depth,
            task_context=self.task_context,
            nonce=self.nonce,
            signature=self.signature,
        )


class RevokeRequest(BaseModel):
    signature: str  # Ed25519 signature authorizing the revocation


class DelegationVerifyResponse(BaseModel):
    verified: bool
    reason: str | None = None
    effective_capabilities: list[str] = []
    chain_depth: int = 0
    delegate_card_id: str | None = None
    root_delegator_card_id: str | None = None
    expires_at: str | None = None


class DelegationsListResponse(BaseModel):
    granted: list[dict] = []
    received: list[dict] = []


# ── Dependency stub — replace with real DB layer ──────────────────────────────

class Database:
    """Stub database layer. Replace with real async DB client."""

    async def get_agent(self, agent_id: str) -> dict | None:
        raise NotImplementedError("Wire up real DB")

    async def get_delegation(self, delegation_id: str) -> dict | None:
        raise NotImplementedError("Wire up real DB")

    async def create_delegation(self, req: DelegationCreateRequest) -> str:
        raise NotImplementedError("Wire up real DB")

    async def update_delegation_status(self, delegation_id: str, status: str) -> None:
        raise NotImplementedError("Wire up real DB")

    async def list_delegations(self, **filters) -> list[dict]:
        raise NotImplementedError("Wire up real DB")


def get_db() -> Database:
    return Database()


def _verify_revocation_signature(signature: str, delegation: dict) -> bool:
    """Stub: replace with real Ed25519 verification against delegator's public key."""
    raise NotImplementedError("Wire up Ed25519 revocation signature verification")


# ── POST /delegations ─────────────────────────────────────────────────────────

@router.post("/delegations", status_code=201)
async def create_delegation_record(
    req: DelegationCreateRequest,
    db: Database = Depends(get_db),
) -> dict:
    """
    Accept a signed delegation token and store it in ARIA.

    Validation sequence:
    1. Delegator card exists and is active
    2. Delegate card exists
    3. Token signature is valid (via verify_delegation)
    4. Delegated capabilities are subset of delegator's
    5. expires_at is not past
    6. expires_at does not exceed delegator card's expires_at
    7. If parent_delegation_id: parent exists, caps subset, depth/TTL constraints
    """
    delegator_card = await db.get_agent(req.delegator_card_id)
    if not delegator_card:
        raise HTTPException(404, f"Delegator card {req.delegator_card_id} not found")

    delegate_card = await db.get_agent(req.delegate_card_id)
    if not delegate_card:
        raise HTTPException(404, f"Delegate card {req.delegate_card_id} not found")

    token = req.to_delegation_token()

    result = verify_delegation(
        token=token,
        delegator_card=delegator_card,
    )
    if not result.valid:
        raise HTTPException(400, f"Invalid delegation: {result.reason}")

    if req.parent_delegation_id:
        parent = await db.get_delegation(req.parent_delegation_id)
        if not parent or parent.get("status") != "active":
            raise HTTPException(400, "Parent delegation not found or inactive")

        try:
            validate_capability_subset(
                req.delegated_capabilities,
                parent["delegated_capabilities"],
            )
        except CapabilityEscalation as e:
            raise HTTPException(400, f"Capabilities exceed parent delegation: {e}")

        if req.max_redelegation_depth >= parent.get("max_redelegation_depth", 0):
            raise HTTPException(
                400,
                "max_redelegation_depth must be less than parent's depth",
            )

    delegation_id = await db.create_delegation(req)
    return {"id": delegation_id, "status": "active"}


# ── GET /delegations/{id}/verify ─────────────────────────────────────────────

@router.get("/delegations/{delegation_id}/verify")
async def verify_delegation_endpoint(
    delegation_id: str,
    db: Database = Depends(get_db),
) -> DelegationVerifyResponse:
    """
    Walk the delegation chain back to root and verify every link.
    Returns effective capabilities of the final delegate.
    """
    current_record = await db.get_delegation(delegation_id)
    if not current_record:
        raise HTTPException(404, f"Delegation {delegation_id} not found")

    chain: list[dict] = []
    current = current_record
    chain.insert(0, current)

    while current.get("parent_delegation_id"):
        parent = await db.get_delegation(current["parent_delegation_id"])
        if not parent:
            return DelegationVerifyResponse(
                verified=False,
                reason="broken_chain",
            )
        chain.insert(0, parent)
        current = parent

    root_card = await db.get_agent(chain[0]["delegator_card_id"])
    if not root_card:
        return DelegationVerifyResponse(
            verified=False,
            reason="root_card_not_found",
        )

    tokens = [DelegationToken.from_dict(d) for d in chain]
    result = verify_delegation_chain(tokens=tokens, root_card=root_card)

    return DelegationVerifyResponse(
        verified=result.valid,
        reason=result.reason,
        effective_capabilities=result.capabilities if result.valid else [],
        chain_depth=result.chain_depth,
        delegate_card_id=result.delegate_card_id,
        root_delegator_card_id=result.delegator_card_id,
        expires_at=result.expires_at,
    )


# ── GET /agents/{id}/delegations ─────────────────────────────────────────────

@router.get("/agents/{agent_id}/delegations")
async def list_agent_delegations(
    agent_id: str,
    direction: str = "both",
    db: Database = Depends(get_db),
) -> DelegationsListResponse:
    """
    List active delegations granted by or received by an agent.
    direction: "granted" | "received" | "both"
    """
    if direction not in ("granted", "received", "both"):
        raise HTTPException(400, "direction must be 'granted', 'received', or 'both'")

    granted: list[dict] = []
    received: list[dict] = []

    if direction in ("granted", "both"):
        granted = await db.list_delegations(delegator_card_id=agent_id, status="active")

    if direction in ("received", "both"):
        received = await db.list_delegations(delegate_card_id=agent_id, status="active")

    return DelegationsListResponse(granted=granted, received=received)


# ── POST /delegations/{id}/revoke ─────────────────────────────────────────────

@router.post("/delegations/{delegation_id}/revoke")
async def revoke_delegation(
    delegation_id: str,
    req: RevokeRequest,
    db: Database = Depends(get_db),
) -> dict:
    """
    Revoke a delegation and all child delegations (cascade).
    Requires the delegator's Ed25519 signature to authorize.
    """
    delegation = await db.get_delegation(delegation_id)
    if not delegation:
        raise HTTPException(404, f"Delegation {delegation_id} not found")

    if not _verify_revocation_signature(req.signature, delegation):
        raise HTTPException(403, "Unauthorized: revocation signature invalid")

    await db.update_delegation_status(delegation_id, "revoked")

    children = await db.list_delegations(parent_delegation_id=delegation_id)
    for child in children:
        await db.update_delegation_status(child["id"], "revoked")

    return {"revoked": True, "cascade_count": len(children)}
