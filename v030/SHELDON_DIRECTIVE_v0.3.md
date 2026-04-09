# DIRECTIVE: Carapace/ARIA v0.3 — Delegation Chains
## Priority: This is the time-sensitive feature. Ship before LangGraph/AutoGen go enterprise.
## Date: April 8, 2026
## Prerequisite: v0.2 (enforcement, expiry, versioning) must be wired in first.

---

## What This Package Contains

```
carapace-v0.3/
├── DELEGATION_DESIGN.md          # Architecture & design rationale
├── SHELDON_DIRECTIVE_v0.3.md     # This file
├── python/
│   ├── carapace/
│   │   ├── delegation.py         # Core implementation (44/44 tests passing)
│   │   ├── enforce.py            # v0.2 dep (unchanged)
│   │   ├── expiry.py             # v0.2 dep (unchanged)
│   │   └── versioning.py         # v0.2 dep (unchanged)
│   └── tests/
│       └── test_delegation.py    # 44 tests
├── typescript/
│   └── src/
│       └── delegation.ts         # TypeScript mirror
└── aria-schema/
    └── ARIA_DELEGATION_ENDPOINTS.py  # 5 new endpoints + DB migration
```

---

## The Core Invariant

**A delegate can never hold more capabilities than its delegator.**

Every link in a delegation chain can only narrow, never widen. This is
enforced cryptographically — the delegator signs the capability subset
into the token. Chain verification walks the full chain and confirms
every link narrows.

---

## Deliverable 1: Database + Token Storage

1. Run the migration in `ARIA_DELEGATION_ENDPOINTS.py` section 1.
2. Creates `delegation_tokens` table with indexes.
3. Straightforward — no code changes beyond the SQL.

---

## Deliverable 2: POST /aria/v1/delegations

Accept signed delegation tokens and store them. This is the registration
equivalent for delegations. Pseudocode in section 2 of the endpoints file.

Key validation sequence:
- Delegator card exists and is active
- Token signature is valid (Ed25519, same verify you already use)
- Capabilities ⊆ delegator's card capabilities
- TTL ≤ delegator's card TTL
- If re-delegation: capabilities ⊆ parent delegation's capabilities

---

## Deliverable 3: GET /aria/v1/delegations/:id/verify

Chain verification endpoint. Walks `parent_delegation_id` back to root,
fetches the root card, calls `verify_delegation_chain()` from the module.

This is the endpoint that LangGraph/AutoGen workflows would hit to confirm
a sub-agent's authority before allowing a tool call.

---

## Deliverable 4: Supporting Endpoints

- `GET /agents/:id/delegations` — list delegations granted/received
- `POST /delegations/:id/revoke` — explicit revocation with cascade
- Card revocation cascade — when a card is revoked, all its delegations die

---

## Deliverable 5: SDK Methods

Add to both Python and TypeScript clients:
- `client.create_delegation(...)` → posts to `/delegations`
- `client.verify_delegation(id)` → calls `/delegations/:id/verify`
- `client.list_delegations(agent_id, direction)` → calls `/agents/:id/delegations`
- `client.revoke_delegation(id)` → calls `/delegations/:id/revoke`
- `client.redelegate(...)` → convenience for creating chain links

Bump SDK to 0.3.0 on both npm and PyPI.

---

## Design Decisions Worth Knowing

**Why delegations always expire:** No permanent delegations allowed. Even if
the delegator's card has no expiry, delegations default to 24h max. This prevents
stale delegations accumulating — the SOC 2 / FedRAMP angle from v0.2's card TTL
applies doubly here.

**Why max_redelegation_depth exists:** Without it, A→B→C→D→E→F→... is unbounded.
Hard cap is 5 levels. Each re-delegation decrements by 1. Most real orchestration
is 2-3 levels deep.

**Why task_context is informational only:** It's for audit logs, not enforcement.
If you tried to enforce it, you'd need semantic matching on freeform text, which
is an unsolved problem. Same reason the roadmap doc flags "AI vetting assistant"
as theater.

**Cascading revocation:** Revoking a delegation automatically revokes all children.
Revoking a card revokes all its delegations. This is the "pull the plug" mechanism.

**The enforcement module (v0.2) is the foundation:** `validate_capability_subset()`
from the delegation module reuses the wildcard matching logic from `enforce.py`.
Delegation chains sit on top of enforcement hooks — that's why v0.2 shipped first.

---

## Integration Points

**RelayForge Wizard:** When the wizard configures a user's agent, it can
delegate narrow capabilities from the platform agent to the user's agent.
The user's agent can then re-delegate to sub-agents it spawns.

**InstruMate OS:** The 4-agent swarm uses delegation chains naturally.
Librarian delegates read access to Compliance Vault. Math Wiz gets
calculation capabilities. Safety Auditor gets audit-scope read but no write.

**Trust Store Vetting:** When Grok scans a tool, it operates under a
delegation from Sheldon — scoped to read-only analysis capabilities.
GPT's red-teaming operates under a separate, tighter delegation.

---

## What's Left After This

From the original roadmap, still unbuilt:
- **Epistemic Tracking** (v0.4) — tamper-evident provenance logs
- **Compliance Profiles** (v0.4) — named policy bundles
- **Human-in-the-Loop Escalation** (v0.4) — requires_human_approval flag
- **Legal Entity Binding** (v1.0) — OwnerBlock → LLC/corp
- **Cryptographic Audit Logs** (v1.0) — hash-chained verification ledger
- **WASM Browser Verification** (v1.0) — client-side verifyLocal()

🦞
