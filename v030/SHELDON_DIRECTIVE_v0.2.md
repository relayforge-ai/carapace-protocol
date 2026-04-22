# DIRECTIVE: Carapace/ARIA v0.2 Integration
## Priority: Ship in order listed
## Date: April 8, 2026

---

## What This Package Contains

Three new Python modules + TypeScript mirrors + 56 passing tests + schema docs:

```
carapace-v0.2/
├── python/
│   ├── carapace/
│   │   ├── __init__.py        # Barrel exports
│   │   ├── enforce.py         # Runtime capability enforcement
│   │   ├── expiry.py          # Card TTL / expires_at
│   │   └── versioning.py      # Version chains + supersedes
│   └── tests/
│       └── test_v02_features.py   # 56/56 passing
├── typescript/
│   └── src/
│       ├── index.ts           # Barrel exports
│       ├── enforce.ts         # Mirror of Python enforce
│       ├── expiry.ts          # Mirror of Python expiry
│       └── versioning.ts      # Mirror of Python versioning
└── aria-schema/
    ├── SCHEMA_CHANGES_v0.2.md     # Card schema additions
    └── ARIA_ENDPOINT_CHANGES.py   # FastAPI wiring guide
```

---

## Deliverable 1: Wire `expires_at` into ARIA (smallest change, biggest signal)

**Why first:** One schema field + one verify check = SOC 2 / FedRAMP talking point.

1. Run the Supabase migration in `ARIA_ENDPOINT_CHANGES.py` section 5.
2. Add `expires_at` to the registration Pydantic model (optional, nullable).
3. Include `expires_at` in the JCS canonical payload before signing.
4. In the verify endpoint, call `validate_expiry_for_verify(card)` from `carapace.expiry`.
5. Return `expiry_status` and `hours_remaining` in verify responses.
6. Update both SDK clients to accept `expires_at` in `register()` and return it in `verify()`.

**Test:** Register a card with `expires_at` 5 seconds from now. Wait 6 seconds. Verify. Expect `verified: false, reason: "card_expired"`.

---

## Deliverable 2: Wire versioning into ARIA

**Why second:** Auditors want traceable capability changes. Comes up in every enterprise conversation.

1. Add `card_version`, `supersedes`, `superseded_by` columns (migration in section 5).
2. On registration with `supersedes`:
   - Validate owner key match (use `validate_supersedes_registration()`).
   - Set old card status to `"superseded"` + set `superseded_by`.
3. Build `GET /aria/v1/agents/:id/history` endpoint (pseudocode in section 4).
4. Update verify to return `reason: "card_superseded"` with `successor` field.
5. Add `register_update()` convenience method to both SDKs.

**Test:** Register v1. Register v2 with `supersedes=v1.id`. Verify v1 → expect `card_superseded` with successor pointing to v2. Call `/history` → expect 2-entry chain.

---

## Deliverable 3: Publish enforcement hooks in SDKs

**Why third:** This is client-side only — no ARIA changes needed. Ships as SDK update.

1. Add `enforce.py` and `enforce.ts` to the respective SDK packages.
2. Export from package root.
3. Write SDK README section with usage examples.
4. Bump SDK version to 0.2.0 on both npm and PyPI.

**Test:** Already passing — 56 tests cover enforcement, expiry, and versioning.

---

## What NOT To Do

- Don't build delegation chains yet. That's v0.3 and the design isn't settled.
- Don't build the "AI vetting assistant." The roadmap doc explicitly flags this as theater.
- Don't rename the existing `version` semver field to avoid breaking v0.1.1 clients. Use `card_version` for now; clean it up in v0.3.

---

## Integration Notes

- All three Python modules use duck-typed card interfaces — they work with real AgentCards, dicts, or any object with the right attributes. No SDK import dependency for the core logic.
- The enforcement module checks expiry automatically. If a card is expired, `enforce()` throws `CardExpired` before even checking capabilities. This can be disabled with `check_expiry=False`.
- Wildcard matching works both ways: host can require `carapace:read:*` (any read), and agents can declare `carapace:read:*` (all read). This is intentional for broad-scope agents.
- The `EnforcementPolicy` class lets host systems define access control rules in one place and audit what any card can/can't do. Good for the wizard's guardrails setup.

---

## Carry-Forward

After v0.2 ships, the next priority from the roadmap is **delegation chains** — the hardest unsolved problem and the one with the tightest clock. Multi-agent orchestration (LangGraph, AutoGen) is moving fast. If Carapace doesn't have a delegation story before those become enterprise-standard, it gets bypassed.

🦞
