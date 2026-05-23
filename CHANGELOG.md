# Changelog

All notable changes to the Carapace Protocol are documented here.

## [0.5.0] — 2026-05-23

### Added
- **Catalog sync** — `fetch_catalog()` / `fetchCatalog()` performs an
  ETag-based read of the live ARIA registry catalog with 304 Not Modified
  support. `CatalogEntry`, `CatalogState`, and `GateResult` dataclasses /
  TypeScript types are exported from both SDKs.
- **Gate check** — `run_gate_check()` / `runGateCheck()` runs a five-gate
  pre-call delegation validation: `catalog_membership`, `active_status`,
  `revocation_clear`, `clawmark_gate`, and `delegation_valid`. Fail-open when
  the catalog is unavailable (`mode=fail_open`) and observe-only when
  `trust_gates_enabled=False`.
- **Signed receipts** — `create_receipt()` / `createReceipt()` issues
  SHA-256-hashed call receipts with optional Ed25519 signing over a JCS
  canonicalised payload. `verify_receipt()` / `verifyReceipt()` performs
  signature verification and returns a boolean (never raises).
  `post_receipt()` / `post_receipt_async()` / `postReceipt()` are
  fire-and-forget posts to ARIA that NEVER raise.
- **Delegation chains with replay protection** — receipts and gate-check
  results bind to delegation tokens so call chains can be reconstructed and
  replays detected at the registry boundary.
- **Revocation lookup** — `revocation_clear` gate consults the catalog
  revocation list; revoked agents fail-closed regardless of other gates.
- **Capability profiles** — `catalog_get()` / `catalogGet()` and
  `catalog_is_active()` / `catalogIsActive()` helpers expose per-agent
  scope requirements and Clawmark breakdowns sourced from ARIA.
- Mirrored `carapace/catalog.py` and `carapace/receipt.py` into
  `python/carapace/` so the published wheel ships the v0.5 surface.
- 40 new tests added (`tests/test_v05_phase_b.py`,
  `python/tests/test_v05_phase_b.py`, `typescript/test/v05_receipts.test.js`);
  259 total passing.

### Changed
- Clawmark trust gate now operates on the canonical 0–5 scale
  (`CANONICAL_CLAWMARK_STANDARD.md`). `CatalogEntry.clawmark_score` is a
  `float` (Python) / `number | null` (TypeScript); `from_dict` coerces
  ARIA's `null` (unscored) to `0.0`; default `score_threshold` lowered from
  `80` to `3.0` in both SDKs. Catalog fixtures converted from 0–100 to 0–5.
- TypeScript `sha256Json` now sorts keys recursively so nested object
  hashes are stable across implementations.
- TypeScript receipt signing uses a `CryptoKeyPair` so the receipt's
  `public_key` field is populated automatically.
- TypeScript catalog ETag handling strips the `W/` weak-validator prefix
  before comparison.
- `tsconfig` adds the `DOM` lib so `CryptoKey` / `CryptoKeyPair` types
  resolve.
- Package version bumped to **0.5.0** (`pyproject.toml`,
  `python/pyproject.toml`, `typescript/package.json`).

## [0.4.0] — 2026-05-16

### Added
- **Epistemic tracking** — local, operator-owned hash-chained provenance logs
  with integrity verification, audit export, and query helpers. ARIA does not
  store these logs.
- **Compliance profiles** — Python and TypeScript SDK support for named policy
  bundles, built-in V0.4 profiles, capability/TTL/version/attestation checks,
  and violation/warning reporting.
- **Escalation workflows** — SDK policies and triggers for single capability,
  wildcard, capability-combination, and predicate-based human approval checks.
- Public Python and TypeScript package entrypoints now export the V0.4 modules.

### Changed
- Package metadata and README now describe the V0.4 trust stack consistently.
- Canonical TypeScript package metadata now uses `carapace-sdk` on npm,
  matching the public package and README. `@relayforge/carapace-sdk` remains
  an older registry artifact and `@carapace/sdk` was unpublished manifest drift.
- TypeScript epistemic integrity verification now recomputes entry data hashes,
  not only chain links.
- Legal entity binding remains a future policy hook and is reported as a
  warning when requested, not presented as a shipped V0.4 verifier.

## [0.3.0] — 2026-04-08

### Added
- **Delegation chains** — Agent A can grant Agent B a cryptographically signed
  subset of its capabilities. Chains (A→B→C) are verifiable end-to-end.
  OAuth scopes adapted for agent-to-agent trust.
- `create_delegation()` — mint a signed delegation token with TTL and scoped caps
- `verify_delegation()` — verify a single delegation token against delegator card
- `verify_delegation_chain()` — verify full A→B→C chain against root card
- `enforce_delegated()` — enforce capability check through a delegation token
- ARIA endpoints for delegation registration and verification

### Changed
- ARIA schema updated to support delegation token storage and lookup

## [0.2.0] — 2026-03-30

### Added
- **Enforcement hooks** — runtime middleware that blocks tool calls exceeding
  declared capabilities before execution
- **Card expiry / TTL** — agent cards carry expiry timestamps; expired cards
  fail verification automatically
- **Agent card versioning** — version field on all cards; ARIA rejects
  stale versions on update
- **Capability Epochs** — epistemic trust segmentation across capability changes;
  accumulated trust scores reset on epoch boundary
- Dual-language SDK: Python (`carapace-sdk` on PyPI) and
  TypeScript (`@relayforge/carapace-sdk` on npm)
- Apache 2.0 license
