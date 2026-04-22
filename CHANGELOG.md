# Changelog

All notable changes to the Carapace Protocol are documented here.

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
