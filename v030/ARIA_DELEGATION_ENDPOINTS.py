"""
ARIA v0.3 Endpoint Changes — Delegation Chain Support

New endpoints and database changes for delegation tokens.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 1. DATABASE — New delegation_tokens table
# ═══════════════════════════════════════════════════════════════════════════════

"""
Supabase migration SQL:

CREATE TABLE IF NOT EXISTS delegation_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegator_card_id UUID NOT NULL REFERENCES agents(id),
    delegator_public_key TEXT NOT NULL,
    delegate_card_id UUID NOT NULL REFERENCES agents(id),
    delegated_capabilities JSONB NOT NULL,  -- sorted string array
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    parent_delegation_id UUID REFERENCES delegation_tokens(id),
    max_redelegation_depth INTEGER NOT NULL DEFAULT 2,
    task_context TEXT,
    nonce TEXT NOT NULL,
    signature TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'  -- active, expired, revoked
);

-- Indexes for lookup patterns
CREATE INDEX idx_deleg_delegator ON delegation_tokens(delegator_card_id);
CREATE INDEX idx_deleg_delegate ON delegation_tokens(delegate_card_id);
CREATE INDEX idx_deleg_parent ON delegation_tokens(parent_delegation_id);
CREATE INDEX idx_deleg_expires ON delegation_tokens(expires_at);

-- Automatic expiry cleanup (optional — run as cron)
-- UPDATE delegation_tokens SET status = 'expired' WHERE expires_at < NOW() AND status = 'active';
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 2. NEW ENDPOINT — POST /aria/v1/delegations
# ═══════════════════════════════════════════════════════════════════════════════

"""
Register a delegation token in ARIA. This makes the delegation discoverable
and verifiable by third parties without the delegate having to present the
full token.

@router.post("/delegations")
async def create_delegation_record(req: DelegationCreateRequest):
    '''
    Accepts a signed delegation token and stores it in ARIA.
    
    Pre-registration checks:
    1. Delegator card exists and is active
    2. Delegate card exists
    3. Token signature is valid against delegator's public key
    4. Delegated capabilities are subset of delegator's
    5. expires_at is not past
    6. expires_at does not exceed delegator card's expires_at
    7. If parent_delegation_id is set:
       a. Parent delegation exists and is active
       b. Capabilities are subset of parent's
       c. max_redelegation_depth < parent's
       d. expires_at <= parent's expires_at
    '''
    
    from carapace.delegation import (
        verify_delegation,
        validate_capability_subset,
    )
    
    # Fetch delegator card
    delegator_card = await db.get_agent(req.delegator_card_id)
    if not delegator_card:
        raise HTTPException(404, f"Delegator card {req.delegator_card_id} not found")
    
    # Verify the token
    result = verify_delegation(
        token=req.to_delegation_token(),
        delegator_card=delegator_card,
        verify_signature_fn=ed25519_verify,  # Your Ed25519 verify function
    )
    
    if not result.valid:
        raise HTTPException(400, f"Invalid delegation: {result.reason}")
    
    # Parent chain validation (if re-delegation)
    if req.parent_delegation_id:
        parent = await db.get_delegation(req.parent_delegation_id)
        if not parent or parent.status != "active":
            raise HTTPException(400, "Parent delegation not found or inactive")
        
        validate_capability_subset(
            req.delegated_capabilities,
            parent.delegated_capabilities,
        )
    
    # Store
    delegation_id = await db.create_delegation(req)
    return {"id": delegation_id, "status": "active"}

Pydantic model:

class DelegationCreateRequest(BaseModel):
    delegator_card_id: str
    delegator_public_key: str
    delegate_card_id: str
    delegated_capabilities: list[str]
    expires_at: str
    parent_delegation_id: str | None = None
    max_redelegation_depth: int = 2
    task_context: str | None = None
    nonce: str
    signature: str
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 3. NEW ENDPOINT — GET /aria/v1/delegations/:id/verify
# ═══════════════════════════════════════════════════════════════════════════════

"""
Verify a delegation token, including its full chain if it's a re-delegation.

@router.get("/delegations/{delegation_id}/verify")
async def verify_delegation_endpoint(delegation_id: str):
    '''
    Walks the delegation chain back to the root, verifying each link.
    Returns the effective capabilities of the final delegate.
    '''
    from carapace.delegation import verify_delegation_chain
    
    # Build the chain by walking parent_delegation_id
    chain = []
    current = await db.get_delegation(delegation_id)
    if not current:
        raise HTTPException(404)
    
    chain.insert(0, current)
    while current.parent_delegation_id:
        parent = await db.get_delegation(current.parent_delegation_id)
        if not parent:
            return {"verified": False, "reason": "broken_chain"}
        chain.insert(0, parent)
        current = parent
    
    # Get root delegator's card
    root_card = await db.get_agent(chain[0].delegator_card_id)
    if not root_card:
        return {"verified": False, "reason": "root_card_not_found"}
    
    result = verify_delegation_chain(
        tokens=chain,
        root_card=root_card,
        verify_signature_fn=ed25519_verify,
    )
    
    return {
        "verified": result.valid,
        "reason": result.reason,
        "effective_capabilities": result.capabilities if result.valid else [],
        "chain_depth": result.chain_depth,
        "delegate_card_id": result.delegate_card_id,
        "root_delegator_card_id": result.delegator_card_id,
        "expires_at": result.expires_at,
    }
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 4. NEW ENDPOINT — GET /aria/v1/agents/:id/delegations
# ═══════════════════════════════════════════════════════════════════════════════

"""
List all active delegations granted BY or TO an agent.

@router.get("/agents/{agent_id}/delegations")
async def list_agent_delegations(
    agent_id: str,
    direction: str = "both",  # "granted", "received", "both"
):
    results = {"granted": [], "received": []}
    
    if direction in ("granted", "both"):
        results["granted"] = await db.list_delegations(
            delegator_card_id=agent_id, status="active"
        )
    
    if direction in ("received", "both"):
        results["received"] = await db.list_delegations(
            delegate_card_id=agent_id, status="active"
        )
    
    return results
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 5. NEW ENDPOINT — POST /aria/v1/delegations/:id/revoke
# ═══════════════════════════════════════════════════════════════════════════════

"""
Explicitly revoke a delegation. Requires the delegator's signature.

@router.post("/delegations/{delegation_id}/revoke")
async def revoke_delegation(delegation_id: str, req: RevokeRequest):
    '''
    Revokes a delegation and ALL child delegations in the chain.
    Cascading revocation — if you revoke A→B, then B→C is also revoked.
    '''
    delegation = await db.get_delegation(delegation_id)
    if not delegation:
        raise HTTPException(404)
    
    # Verify revocation is authorized (delegator's signature)
    if not verify_revocation_signature(req.signature, delegation):
        raise HTTPException(403, "Unauthorized revocation")
    
    # Revoke this delegation
    await db.update_delegation_status(delegation_id, "revoked")
    
    # Cascade: revoke all children
    children = await db.list_delegations(parent_delegation_id=delegation_id)
    for child in children:
        await db.update_delegation_status(child.id, "revoked")
        # Recursive — could also be done as a single SQL UPDATE
    
    return {"revoked": True, "cascade_count": len(children)}
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 6. CARD REVOCATION CASCADE
# ═══════════════════════════════════════════════════════════════════════════════

"""
When a Carapace card is revoked (existing endpoint), ALL delegations
issued by that card must also be invalidated. Add this to the existing
card revocation handler:

    # In the existing revoke_agent endpoint:
    async def revoke_agent(agent_id: str, ...):
        # ... existing revocation logic ...
        
        # NEW: cascade to delegations
        await db.execute(
            "UPDATE delegation_tokens SET status = 'revoked' "
            "WHERE delegator_card_id = $1 AND status = 'active'",
            agent_id
        )
        
        # Also cascade through re-delegations
        # (children of revoked delegations get revoked too)
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 7. SDK CLIENT ADDITIONS
# ═══════════════════════════════════════════════════════════════════════════════

"""
Both Python and TypeScript SDKs need:

client.create_delegation(
    delegate_card_id="uuid",
    capabilities=["carapace:read:email"],
    ttl_hours=4,
    task_context="Process invoices",
) -> DelegationToken

client.verify_delegation(delegation_id) -> DelegationVerifyResult

client.list_delegations(
    agent_id="uuid",
    direction="both",  # "granted" | "received" | "both"
) -> list[DelegationToken]

client.revoke_delegation(delegation_id) -> bool

client.redelegate(
    parent_delegation_id="uuid",
    delegate_card_id="uuid",
    capabilities=[...],  # Must be subset of parent's
    ttl_hours=2,
) -> DelegationToken
"""
