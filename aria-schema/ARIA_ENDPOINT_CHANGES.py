"""
ARIA v0.2 Endpoint Changes — FastAPI Implementation Guide

This file documents the changes Sheldon needs to make to the ARIA
FastAPI backend to support Carapace v0.2 features.

Current endpoint: relayforge.tools/aria/v1
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 1. SCHEMA CHANGES — Registration Request Model
# ═══════════════════════════════════════════════════════════════════════════════

"""
Existing Pydantic model needs these new optional fields:

class AgentRegistration(BaseModel):
    name: str
    description: str
    framework: str
    capabilities: list[Capability]
    endpoints: list[Endpoint]
    version: str | None = None       # existing semver field
    tags: list[str] = []
    metadata: dict = {}
    
    # ── NEW v0.2 fields ──
    expires_at: str | None = None     # ISO 8601, nullable
    card_version: int = 1             # Integer version counter (NOT the semver field)
    supersedes: str | None = None     # UUID of predecessor card

Note: 'card_version' avoids collision with the existing 'version' semver field.
If you prefer to rename the existing field to 'semver' and reclaim 'version'
for the integer, that's cleaner but is a breaking change for v0.1.1 clients.
Recommendation: use 'card_version' for now, rename in v0.3 with a migration.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 2. REGISTRATION ENDPOINT — POST /aria/v1/agents
# ═══════════════════════════════════════════════════════════════════════════════

"""
Changes to the registration handler:

1. Accept expires_at, card_version, supersedes in the request body.

2. If supersedes is provided:
   a. Fetch the superseded card from the database.
   b. Verify the registering owner's public key matches the superseded card's owner.
      Use: validate_supersedes_registration(new_owner_key, superseded_card)
      from carapace.versioning
   c. If mismatch → 403 Forbidden with clear error.
   d. If match → set superseded card's status to "superseded" and add
      superseded_by = new_card.id to the old card's record.

3. Include expires_at, card_version, supersedes in the JCS canonical payload
   BEFORE signing. This means these fields are covered by the signature.

4. Store all new fields in the database alongside existing card data.

Pseudocode:

@router.post("/agents")
async def register_agent(req: AgentRegistration, ...):
    # ... existing validation ...
    
    if req.supersedes:
        old_card = await db.get_agent(req.supersedes)
        if not old_card:
            raise HTTPException(404, f"Superseded card {req.supersedes} not found")
        
        validate_supersedes_registration(
            new_owner_key=derived_public_key,
            superseded_card=old_card,
        )
        
        # Mark old card as superseded (after new card is created)
    
    card_payload = {
        **existing_fields,
        "expires_at": req.expires_at,
        "card_version": req.card_version,
        "supersedes": req.supersedes,
    }
    
    # JCS canonicalize → Ed25519 sign → store
    
    if req.supersedes:
        await db.update_agent_status(req.supersedes, "superseded", superseded_by=new_card.id)
    
    return new_card
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 3. VERIFY ENDPOINT — GET /aria/v1/agents/:id/verify
# ═══════════════════════════════════════════════════════════════════════════════

"""
Changes to the verify handler:

1. After signature verification passes, check expiry:
   
   from carapace.expiry import validate_expiry_for_verify
   
   expiry_result = validate_expiry_for_verify(card)
   if not expiry_result["passed"]:
       return {
           "verified": False,
           "reason": expiry_result["reason"],
           "expired": True,
           "expires_at": card.expires_at,
       }

2. Check superseded status:
   
   if card.status == "superseded":
       return {
           "verified": False,
           "reason": "card_superseded",
           "successor": card.superseded_by,
       }

3. Add expiry_status to successful verify responses:
   
   return {
       "verified": True,
       "agent": card,
       "expiry_status": expiry_result["status"],  # "valid", "expiring_soon", "no_expiry"
       "hours_remaining": expiry_result.get("hours_remaining"),
   }
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 4. NEW ENDPOINT — GET /aria/v1/agents/:id/history
# ═══════════════════════════════════════════════════════════════════════════════

"""
Version history endpoint. Returns the full supersedes chain for an agent lineage.

@router.get("/agents/{agent_id}/history")
async def get_version_history(agent_id: str):
    '''
    Walk the supersedes chain backward from the given card,
    then walk superseded_by forward to get the full lineage.
    '''
    # Start with the requested card
    card = await db.get_agent(agent_id)
    if not card:
        raise HTTPException(404)
    
    chain = [card]
    
    # Walk backward (supersedes)
    current = card
    while current.supersedes:
        predecessor = await db.get_agent(current.supersedes)
        if not predecessor:
            break
        chain.insert(0, predecessor)
        current = predecessor
    
    # Walk forward from the requested card (superseded_by)
    current = card
    while current.superseded_by:
        successor = await db.get_agent(current.superseded_by)
        if not successor:
            break
        chain.append(successor)
        current = successor
    
    # Validate the chain
    from carapace.versioning import validate_version_chain
    validated = validate_version_chain(chain)
    
    return {
        "agent_id": agent_id,
        "lineage_length": validated.length,
        "current": validated.current,
        "original": validated.original,
        "history": [
            {
                "card_id": e.card_id,
                "version": e.version,
                "status": e.status,
                "supersedes": e.supersedes,
                "superseded_by": e.superseded_by,
                "created_at": e.created_at,
            }
            for e in validated.entries
        ],
    }
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 5. DATABASE SCHEMA CHANGES
# ═══════════════════════════════════════════════════════════════════════════════

"""
Supabase migration SQL:

ALTER TABLE agents
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS card_version INTEGER DEFAULT 1,
  ADD COLUMN IF NOT EXISTS supersedes UUID DEFAULT NULL REFERENCES agents(id),
  ADD COLUMN IF NOT EXISTS superseded_by UUID DEFAULT NULL;

-- Index for version history queries
CREATE INDEX IF NOT EXISTS idx_agents_supersedes ON agents(supersedes);
CREATE INDEX IF NOT EXISTS idx_agents_superseded_by ON agents(superseded_by);

-- Add 'superseded' to the status enum if using one
-- (or just use text — simpler for now)
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 6. CLIENT SDK CHANGES (both Python and TypeScript)
# ═══════════════════════════════════════════════════════════════════════════════

"""
client.register() — Accept new optional params:
    card = client.register(
        name="ResearchAgent",
        ...,
        expires_at="2026-09-01T00:00:00Z",  # NEW
        card_version=2,                       # NEW
        supersedes="old-uuid",                # NEW
    )

client.verify() — Return new fields in VerifyResult:
    result.expiry_status   # "valid" | "expired" | "expiring_soon" | "no_expiry"
    result.hours_remaining # float | None
    result.successor       # str | None (if superseded)

client.get_version_history(agent_id) — NEW method:
    history = client.get_version_history("uuid")
    # Returns VersionChain with full lineage

client.register_update(supersedes_card, **new_fields) — NEW convenience method:
    # Automatically sets card_version and supersedes
    from carapace.versioning import prepare_version_fields
    fields = prepare_version_fields(supersedes_card)
    return client.register(**new_fields, **fields)
"""
