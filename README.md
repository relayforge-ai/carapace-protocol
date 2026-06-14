<p align="center">
  <img src="docs/carapace-logo.png" alt="Carapace Protocol" width="200" />
</p>

<h1 align="center">🛡️ Carapace Protocol</h1>

<h3 align="center">Cryptographic identity, capability verification, and trust delegation<br/>for AI agents. Open standard. No vendor lock-in.</h3>

<p align="center">
  <a href="https://api.relayforge.tools/aria/v1/docs">ARIA Registry</a> •
  <a href="https://relayforge.tools/whitepaper">Whitepaper</a> •
  <a href="https://www.npmjs.com/package/carapace-sdk">npm</a> •
  <a href="https://pypi.org/project/carapace-sdk/">PyPI</a> •
  <a href="https://relayforge.tools">RelayForge</a> •
  <a href="https://discord.gg/relayforge">Discord</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v0.5.0-C45E2A?style=flat-square" alt="v0.5.0" />
  <img src="https://img.shields.io/badge/spec_license-CC_BY_4.0-4CAF50?style=flat-square" alt="CC BY 4.0" />
  <img src="https://img.shields.io/badge/crypto-Ed25519%2FJCS-F5F0E8?style=flat-square&labelColor=0A0A0A" alt="Ed25519/JCS" />
  <img src="https://img.shields.io/npm/v/carapace-sdk?style=flat-square&label=npm&color=C45E2A" alt="npm version" />
  <img src="https://img.shields.io/pypi/v/carapace-sdk?style=flat-square&label=pypi&color=C45E2A" alt="PyPI version" />
</p>

---

> **The agent ecosystem has a trust problem.** Tools are shipping faster than anyone can vet them. Agents are acting on behalf of humans with no verifiable identity. Carapace exists to fix that — with cryptography, not promises.

---

## The Problem

Every agent platform lets agents call tools. Almost none of them answer these questions:

- **Who built this tool?** No cryptographic proof of authorship.
- **What can it actually do?** Capability claims aren't verifiable.
- **What changed since last time?** No auditable mutation history.
- **Why should an agent — or a human — trust it?** Because the README said so?

Carapace answers all four. With Ed25519 signatures, JCS canonicalization, and the ARIA registry as the public ledger.

<br/>

## How It Works

```
┌──────────────────────────────────────────────┐
│              CARAPACE IDENTITY                │
│                                               │
│  Ed25519 keypair → agent identity             │
│  JCS canonicalization → deterministic signing  │
│  ARIA registration → public verification      │
│  Capability attestation → what it can do      │
│  Epistemic tracking → what it knows (v0.4)    │
└──────────────────────────────────────────────┘
```

Every Carapace-wrapped agent gets:

| Component | What It Does |
|:----------|:-------------|
| **Identity Card** | Ed25519 public key as the agent's verifiable identity |
| **Capability Manifest** | Cryptographically signed declaration of what the agent can do |
| **Provenance Chain** | Auditable history of tool use, capability changes, and trust delegations |
| **Epistemic Record** | What the agent knows, how it knows it, and confidence levels (v0.4.0) |

<br/>

## Installation

```bash
# JavaScript/TypeScript
npm install carapace-sdk

# Python
pip install carapace-sdk
```

Canonical package names for `v0.5.0` are `carapace-sdk` on npm and
`carapace-sdk` on PyPI. Python imports use the `carapace` module.

<br/>

## Audit-Friendly Clone

The current `main` tree is intentionally small, but historical side-branch blobs
can make a normal full clone slow. For standards review, security scanning, or
docs work, use a blobless sparse clone:

```bash
git clone --filter=blob:none --sparse https://github.com/relayforge-ai/carapace-protocol.git
cd carapace-protocol
git sparse-checkout set README.md docs carapace python typescript tests
```

See [Repository Weight](docs/REPOSITORY_WEIGHT.md) for the current weight audit,
known historical artifact sources, and cleanup plan.

<br/>

## Quick Start

**JavaScript/TypeScript:**

```typescript
import {
  BUILTIN_PROFILES,
  EpistemicLog,
  evaluateCompliance,
  enforce,
  hashData,
  makeExpiresAt,
} from 'carapace-sdk';

const card = {
  id: 'agent-1',
  capabilities: [{ id: 'carapace:read:calendar' }],
  expires_at: makeExpiresAt({ ttlHours: 24 }),
  card_version: 2,
  framework: 'custom',
};

enforce(card, 'carapace:read:calendar');

const result = evaluateCompliance(
  card,
  BUILTIN_PROFILES['carapace-profile:general-saas'],
);
console.log(result.compliant);

const log = new EpistemicLog('agent-1');
await log.record({
  action: 'checked_calendar_policy',
  sources: [{ agent_id: 'planner', data_hash: await hashData('policy') }],
  confidence: 0.9,
});
```

**Python:**

```python
from carapace import (
    BUILTIN_PROFILES,
    EpistemicLog,
    Source,
    enforce,
    evaluate_compliance,
    hash_data,
    make_expires_at,
)

card = {
    "id": "agent-1",
    "capabilities": [{"id": "carapace:read:calendar"}],
    "expires_at": make_expires_at(ttl_hours=24),
    "card_version": 2,
    "framework": "custom",
}

enforce(card, "carapace:read:calendar")

result = evaluate_compliance(
    card,
    BUILTIN_PROFILES["carapace-profile:general-saas"],
)
print(result.compliant)

log = EpistemicLog(agent_id="agent-1")
log.record(
    action="checked_calendar_policy",
    sources=[Source(agent_id="planner", data_hash=hash_data("policy"))],
    confidence=0.9,
)
```

<br/>

## ARIA Registry

ARIA (Agent Registry & Identity Authority) is the FastAPI backend that serves as the public ledger for Carapace identities.

| Endpoint | Purpose |
|:---------|:--------|
| `GET /aria/v1/agents/{id}` | Look up an agent's identity and capabilities |
| `POST /aria/v1/agents` | Register a new agent |
| `GET /aria/v1/agents/{id}/provenance` | Audit trail for an agent's actions |
| `POST /aria/v1/verify` | Verify a signed capability or action |

Base URL: `https://api.relayforge.tools/aria/v1`

<br/>

## Roadmap

| Version | Status | Focus |
|:--------|:-------|:------|
| v0.1.0 | ✅ Shipped | Core identity, registration, signing |
| v0.2.0 | ✅ Shipped | Runtime enforcement, expiry, and card versioning |
| v0.3.0 | ✅ Shipped | Delegation chains and protected path guard |
| v0.4.0 | ✅ Shipped | Epistemic tracking, compliance profiles, escalation workflows |
| v0.5.0 | ✅ Current | Active trust-control alignment and registry-facing verification updates |
| v1.0.0 | Planned | Legal entity binding, full A2A commerce support |

<br/>

## Standards Contributions

Carapace has been submitted as a standards contribution to:

- **NIST** — Agent identity and trust infrastructure
- **ISA** — Industrial AI safety and verification

The whitepaper covering consumer and industrial safety is published at [relayforge.tools/whitepaper](https://relayforge.tools/whitepaper).

<br/>

## Design Principles

1. **Cryptography, not promises.** If it can't be verified with a signature, it's not trust.
2. **Open standard, not a product moat.** Spec is CC BY 4.0. Build on it.
3. **Portable trust.** If trust only works inside one vendor's app, it's not durable.
4. **Works with MCP.** Carapace wraps existing protocols — it doesn't replace them.
5. **Industrial-grade.** If it can't satisfy a refinery compliance review, it's not ready.

<br/>

## Related Repositories

| Repo | Purpose |
|:-----|:--------|
| [relayforge](https://github.com/ryan10sa-star/relayforge) | Main site, trust layer docs |
| [lobster-runtime](https://github.com/ryan10sa-star/lobster-runtime) | Agent runtime (Carapace integrated) |
| [relayforge-wizard](https://github.com/ryan10sa-star/relayforge-wizard) | Lobster Launcher frontend |

<br/>

---

<p align="center">
  <sub>Part of <a href="https://relayforge.tools">RelayForge</a> · Spec license: CC BY 4.0 · Anacortes, WA</sub>
</p>
