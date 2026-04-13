# Delegation Chains — Design Document
## Carapace v0.3

---

## The Problem

Agent A spawns Agent B to handle a subtask. Agent B needs to call tools
on Agent A's behalf. Today, Agent B needs its own full independent credentials.
That defeats the purpose of orchestration and creates a capability sprawl problem
where every sub-agent has more access than it needs.

## The OAuth Analogy

OAuth scopes solve this for humans: an app gets a token with a subset of
your permissions, time-limited, revocable. Delegation chains are the same
pattern for agent-to-agent trust.

## Core Invariant

**A delegate can never hold more capabilities than its delegator.**
Each link in the chain can only narrow, never widen. This is enforced
cryptographically — the delegator signs the capability subset into the token.

---

## Token Structure

```json
{
  "id": "delegation-uuid",
  "delegator_card_id": "agent-a-uuid",
  "delegator_public_key": "hex...",
  "delegate_card_id": "agent-b-uuid",
  "delegated_capabilities": [
    "carapace:read:email",
    "carapace:write:email"
  ],
  "expires_at": "2026-04-09T12:00:00Z",
  "created_at": "2026-04-08T12:00:00Z",
  "parent_delegation_id": null,
  "max_redelegation_depth": 2,
  "task_context": "Process Q2 invoices from inbox",
  "nonce": "random-hex-16",
  "signature": "hex..."
}
```

### Field semantics:

- **delegator_card_id** — Who is granting. Must be a valid, non-expired Carapace card.
- **delegator_public_key** — The delegator's Ed25519 public key (for offline verification).
- **delegate_card_id** — Who is receiving. Must be a valid Carapace card.
- **delegated_capabilities** — MUST be a subset of the delegator's declared capabilities.
  If the delegator has a wildcard (carapace:read:*), the delegation can narrow to
  specific resources (carapace:read:email).
- **expires_at** — REQUIRED. Delegations always expire. No permanent delegations.
  Must not exceed the delegator's own card expiry.
- **parent_delegation_id** — If this delegation is a re-delegation (B delegating to C
  from A's original grant), this points to the parent token. Null for root delegations.
- **max_redelegation_depth** — How many more times this can be re-delegated. 0 = terminal.
  Each re-delegation decrements by 1. Cannot exceed parent's remaining depth.
- **task_context** — Optional human-readable description of what this delegation is for.
  Informational only — not enforced, but shows up in audit logs.
- **nonce** — Random value to prevent replay. Included in signature.
- **signature** — Ed25519 signature over the JCS-canonical token payload (minus signature field).

### Signing

The delegator signs the token with their Ed25519 private key. The same key
that signed their Carapace card signs the delegation token. This creates a
cryptographic chain: card → delegation → (optional re-delegation).

Verification:
1. Verify the token signature against the delegator's public key
2. Verify the delegator's card is valid (not expired, not revoked, not superseded)
3. Verify delegated_capabilities ⊆ delegator's card capabilities
4. Verify expires_at hasn't passed
5. Verify expires_at ≤ delegator's card expires_at (if set)
6. If parent_delegation_id exists, verify the parent chain recursively

---

## Chain Verification

For a chain A → B → C:

```
Token 1: A delegates [read, write, execute] to B, depth=2
Token 2: B delegates [read, write] to C, depth=1  (narrowed, depth decremented)
```

Verification of C's authority:
1. Verify Token 2 (B→C): signature, expiry, capabilities
2. Verify Token 1 (A→B): signature, expiry, capabilities  
3. Verify Token 2's capabilities ⊆ Token 1's capabilities (chain narrowing)
4. Verify Token 2's expires_at ≤ Token 1's expires_at
5. Verify Token 2's parent_delegation_id = Token 1's id
6. Verify A's card is valid
7. Token 1's capabilities ⊆ A's card capabilities

If any link fails, the entire chain fails.

---

## Revocation

Two mechanisms:
1. **TTL expiry** — the primary mechanism. Short-lived delegations are the default.
2. **Card revocation** — if the delegator's card is revoked, ALL delegations
   issued by that card become invalid (because step 2 of verification fails).
3. **Future: explicit revocation registry** — ARIA could maintain a delegation
   revocation list. Not in v0.3 scope — TTL + card revocation covers the
   critical cases.

---

## Constraints

- max_redelegation_depth hard cap: 5 (configurable per deployment)
- Delegation TTL hard cap: cannot exceed delegator's card TTL
- Delegations without card expiry: max 24 hours (configurable)
- A delegation token is ~500 bytes. A 5-deep chain is ~2.5KB. Acceptable.

---

## What This Enables

1. LangGraph workflows: orchestrator agent delegates specific capabilities
   to worker agents per step
2. AutoGen multi-agent: supervisor hands scoped authority to specialists
3. RelayForge wizard: the wizard can delegate narrow tool access to the
   user's configured agent without giving it full platform access
4. Enterprise: delegation chains create a complete audit trail of who
   authorized what for whom

---

## What This Does NOT Solve (v0.4+)

- Delegation to anonymous/unregistered agents (requires card)
- Capability negotiation (agent B requesting specific capabilities from A)
- Delegation marketplaces (agents advertising available delegations)
- Cross-registry delegation (agents registered in different ARIA instances)
