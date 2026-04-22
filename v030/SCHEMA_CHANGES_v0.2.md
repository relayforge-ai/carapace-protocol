# Carapace v0.2 Schema Changes

## Card Schema Additions

### 1. `expires_at` (Card Expiry / TTL)

New **optional** field on the AgentCard, covered by the Ed25519 signature.

```json
{
  "id": "uuid",
  "name": "ResearchAgent",
  "owner": { "public_key": "hex..." },
  "capabilities": [...],
  "endpoints": [...],
  "expires_at": "2026-06-01T00:00:00Z",   // ← NEW (ISO 8601, nullable)
  "signature": "hex..."
}
```

**Rules:**
- `expires_at` is included in the JCS canonical payload before signing.
- If `expires_at` is `null` or absent, the card has no expiry (v0.1.1 behavior).
- `verify()` and `verifyLocal()` MUST check `expires_at` against current UTC time.
- Expired cards return `{ verified: false, reason: "card_expired" }`.
- Expired cards remain in ARIA for audit — they are NOT deleted.
- Re-registration with a new `expires_at` produces a new card (see versioning).

**ARIA endpoint changes:**
- `POST /aria/v1/agents` accepts `expires_at` in the registration body.
- `GET /aria/v1/agents/:id` returns `expires_at` in the card.
- `GET /aria/v1/agents/:id/verify` returns `expired: true` alongside `verified: false` when TTL exceeded.

---

### 2. `version` and `supersedes` (Agent Card Versioning)

New fields for traceable capability evolution.

```json
{
  "id": "uuid-v2",
  "name": "ResearchAgent",
  "owner": { "public_key": "hex..." },
  "capabilities": [...],
  "endpoints": [...],
  "expires_at": "2026-09-01T00:00:00Z",
  "version": 2,                           // ← NEW (integer, starts at 1)
  "supersedes": "uuid-v1",                // ← NEW (previous card ID, nullable)
  "signature": "hex..."
}
```

**Rules:**
- `version` is an integer, starting at 1 for new registrations.
- `supersedes` is the UUID of the previous card this one replaces. `null` for v1.
- Both fields are included in the JCS canonical payload before signing.
- When a card with `supersedes` is registered, ARIA:
  1. Verifies the new card's owner public key matches the superseded card's owner.
  2. Sets the superseded card's status to `"superseded"` (not revoked — semantically different).
  3. Stores a forward pointer: superseded card gains `superseded_by: "uuid-v2"`.
- `client.verify()` on a superseded card returns `{ verified: false, reason: "card_superseded", successor: "uuid-v2" }`.
- The full version chain is queryable: `GET /aria/v1/agents/:id/history`.

**ARIA endpoint additions:**
- `GET /aria/v1/agents/:id/history` — returns ordered array of all card versions for this agent lineage.
- `POST /aria/v1/agents` now accepts `version` and `supersedes` in registration body.

---

### 3. Capability Taxonomy (for Enforcement Hooks)

No schema change to the card itself — capabilities still use freeform `id` strings.
But v0.2 introduces a **recommended namespace convention** and a client-side enforcement layer.

**Recommended capability ID format:**
```
carapace:<action>:<resource>

Examples:
  carapace:read:email
  carapace:write:database
  carapace:execute:process_control
  carapace:admin:user_management
```

**Actions:** `read`, `write`, `execute`, `admin`, `delete`
**Resources:** Freeform, but common ones documented in the SDK.

The enforcement layer is purely client-side — it does NOT require ARIA changes.
Host systems call `carapace.enforce(card, "carapace:write:database")` before
allowing a tool call. If the card doesn't declare that capability, it throws.

---

## Migration Notes

- v0.1.1 cards remain valid. Missing `expires_at`, `version`, `supersedes` default to `null`, `1`, `null`.
- No breaking changes to existing `register()` or `verify()` calls.
- New fields are additive and backward-compatible.
- JCS canonicalization handles the new fields automatically (deterministic key ordering).
