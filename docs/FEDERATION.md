# Carapace Federation — Design Specification
**Version:** 0.1.0-draft  
**Status:** Design only — not yet implemented  
**Author:** Ryan S. Anderson, RelayForge  
**Date:** March 2026

---

## Problem Statement

A trust standard that depends on a single hosted registry is fragile. Enterprise and government buyers will not route critical agent workflows through infrastructure controlled by one organization. A standard must have a credible answer to: *"What happens if RelayForge goes down, raises prices, or is acquired?"*

Federation solves this by defining how multiple ARIA-compatible registries can interoperate — so that an agent registered with Registry A can be verified by a host system that only trusts Registry B.

---

## Design Goals

1. **No single point of failure.** Any ARIA-compatible registry can verify any Carapace-signed agent card, regardless of which registry originally issued it.
2. **No required trust in a central authority.** Verification must be possible using only the agent's public key and the signed card — no registry dependency.
3. **Operator choice.** Organizations can self-host a private ARIA registry and federate selectively with public registries.
4. **Backward compatible.** Federation is additive. A single-registry deployment continues to work without changes.

---

## Core Insight

Carapace federation is simpler than most federation protocols because the cryptographic trust is already in the card, not in the registry.

An ARIA registry is a discovery and revocation service. It does not issue trust — it indexes it. The trust anchor is the agent owner's Ed25519 keypair. This means:

> **An agent registered on Registry A can be verified by any party that has the card and the public key, regardless of which registry they query.**

Federation, therefore, is primarily about:
- **Discovery** — finding agents across registries
- **Revocation propagation** — ensuring a revocation on Registry A is visible to verifiers using Registry B
- **Registry trust** — how a verifier decides which registries to query

---

## Architecture

### Registry Identity

Every ARIA-compatible registry has:

- A **Registry ID** — a UUID assigned at initialization
- A **Registry signing keypair** — Ed25519, used to sign the registry's CRL and well-known document
- A **Well-known document** at `/.well-known/aria-registry.json`

```json
{
  "registry_id": "a3f7c2e1-...",
  "name": "RelayForge ARIA",
  "operator": "RelayForge",
  "url": "https://api.relayforge.tools/aria/v1",
  "public_key": "b9e2...",
  "version": "1",
  "federation": {
    "enabled": true,
    "peers": [
      "https://aria.example-org.com/v1",
      "https://aria.industrial-trust.net/v1"
    ]
  },
  "issued_at": "2026-03-01T00:00:00Z",
  "signature": "7f3a..."
}
```

The `peers` array is informational — it tells other registries where to look for federation partners, but does not automatically establish trust.

---

### Agent Card Registry Attribution

Agent cards gain a `registered_with` field in the federated model:

```json
{
  "id": "uuid",
  "name": "ResearchAgent",
  ...
  "registered_with": {
    "registry_id": "a3f7c2e1-...",
    "registry_url": "https://api.relayforge.tools/aria/v1",
    "registry_public_key": "b9e2..."
  },
  "owner": {
    "public_key": "c4d5..."
  },
  "signature": "7f3a..."
}
```

The `registered_with` block is included in the signed payload. This means:
- The agent's owner signature covers which registry the agent is registered with
- A verifier can independently contact that registry to check revocation status
- The registry's own public key is pinned in the card, so the verifier can verify the registry's CRL signature without trusting a DNS lookup

---

### Verification Flow (Federated)

```
Verifier receives agent card
        │
        ▼
verify_local(card, signature, public_key)
        │
        ├── PASS → agent card is authentic and untampered
        │
        ▼
Check revocation:
  1. Try local cache (RevocationCache)
  2. Cache miss → query card.registered_with.registry_url/revocations
  3. Verify CRL signature against card.registered_with.registry_public_key
  4. Check agent_id in CRL entries
        │
        ├── NOT REVOKED → agent is trusted
        └── REVOKED     → reject
```

The verifier never needs to trust the registry operator — they verify the CRL signature independently using the public key pinned in the agent's own card.

---

### Revocation Propagation

When an agent is revoked on Registry A, the revocation must reach verifiers who might be querying Registry B. Two models:

**Model 1 — Pull-based (current, sufficient for v1)**

Verifiers always query `card.registered_with.registry_url` for revocation, regardless of which registry they normally use. Revocation is always authoritative at the issuing registry.

*Pro:* Simple. No inter-registry coordination needed.  
*Con:* Requires contacting the original registry. Fails if Registry A is down.

**Model 2 — Push-based (future)**

Registry A pushes a signed revocation notice to all registered peer registries. Peers cache the revocation and serve it to their own verifiers.

*Pro:* Revocation works even if the original registry is down.  
*Con:* Requires active peer relationships and signed push messages.

**Recommendation:** Implement Model 1 first (it's already 80% built with the revocation list endpoint). Design Model 2 as a v0.3 feature with an explicit peer notification API.

---

### Trust Tiers for Registry Operators

Not all registries should be equally trusted. The Carapace federation model defines three trust tiers:

| Tier | Description | Requirements |
|---|---|---|
| **Tier 0 — Unverified** | Self-registered, no attestation | Anyone can run |
| **Tier 1 — Community** | Operated by a known organization, public contact | Register with RelayForge directory |
| **Tier 2 — Audited** | Third-party security audit of registry infrastructure | Audit report published |
| **Tier 3 — Certified** | Meets ISA/IEC 62443 or equivalent | Formal certification |

Verifiers declare which tiers they accept. Industrial systems might require Tier 2+ for any agent making process control calls.

This is the mechanism that turns Carapace from a protocol into a standards ecosystem — the registry operator certification tier is where RelayForge's long-term authority comes from.

---

## Self-Hosting Guide (Sketch)

A minimal self-hosted ARIA registry requires:

1. **The ARIA FastAPI application** (open source, Apache 2.0)
2. **A PostgreSQL database** (Supabase or self-hosted)
3. **An Ed25519 server keypair** (`aria-server keygen`)
4. **The well-known document** served at `/.well-known/aria-registry.json`
5. **Optional: register as a peer** with RelayForge ARIA for cross-registry discovery

```bash
# Install
pip install aria-server

# Generate server keypair
aria-server keygen --output /etc/aria/server.key

# Initialize database
aria-server db init --url postgresql://...

# Start
aria-server start --port 8001 --key /etc/aria/server.key
```

Full self-hosting documentation: relayforge.tools/docs/self-hosting

---

## What This Enables

Once federation is implemented:

- **Enterprise private registries** — a bank can run their own ARIA, register internal agents, and never expose them to the public registry
- **Industry sector registries** — an industrial consortium can run a Tier 2 ARIA that only admits ISA/IEC 62443-aligned agents
- **Government registries** — a federal agency can run an air-gapped ARIA for classified agent infrastructure
- **No lock-in** — any of these can interoperate with RelayForge ARIA for cross-boundary agent calls

This is the answer to the enterprise buyer question. RelayForge becomes the reference implementation and the Tier 3 certification authority, not the only registry.

---

## Open Questions (Tracking)

- [ ] Should peer relationships be explicit (allow-list) or open (any ARIA-compatible)?
- [ ] What is the format for a signed peer notification in Model 2?
- [ ] Does federation require a governance body, or is the spec sufficient?
- [ ] How does revocation propagate for agents that appear on multiple registries?

---

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | March 2026 | Initial design document |

---

*Carapace Federation Design — RelayForge — Apache 2.0*  
*Feedback: github.com/relayforge/carapace-protocol/issues*
