<p align="center">
  <img src="docs/carapace-logo.png" alt="Carapace Protocol" width="200" />
</p>

<h1 align="center">🛡️ Carapace Protocol</h1>

<h3 align="center">Cryptographic identity, capability verification, and trust delegation<br/>for AI agents. Open standard. No vendor lock-in.</h3>

<p align="center">
  <a href="https://relayforge.tools/aria/v1">ARIA Registry</a> •
  <a href="https://relayforge.tools/whitepaper">Whitepaper</a> •
  <a href="https://www.npmjs.com/package/carapace-sdk">npm</a> •
  <a href="https://pypi.org/project/carapace-sdk/">PyPI</a> •
  <a href="https://relayforge.tools">RelayForge</a> •
  <a href="https://discord.gg/relayforge">Discord</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v0.2.0-C45E2A?style=flat-square" alt="v0.2.0" />
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
│  Epistemology tracking → what it knows (v0.2) │
└──────────────────────────────────────────────┘
```

Every Carapace-wrapped agent gets:

| Component | What It Does |
|:----------|:-------------|
| **Identity Card** | Ed25519 public key as the agent's verifiable identity |
| **Capability Manifest** | Cryptographically signed declaration of what the agent can do |
| **Provenance Chain** | Auditable history of tool use, capability changes, and trust delegations |
| **Epistemology Record** | What the agent knows, how it knows it, and confidence levels (v0.2.0) |

<br/>

## Installation

```bash
# JavaScript/TypeScript
npm install carapace-sdk

# Python
pip install carapace-sdk
```

<br/>

## Quick Start

**JavaScript/TypeScript:**

```typescript
import { CarapaceAgent, AriaRegistry } from 'carapace-sdk';

// Create an agent identity
const agent = await CarapaceAgent.create({
  name: 'my-lobster',
  capabilities: ['email-read', 'calendar-write'],
});

// Register with ARIA
const registry = new AriaRegistry('https://api.relayforge.tools/aria/v1');
await registry.register(agent);

// Sign an action
const signed = agent.sign({ action: 'read-email', timestamp: Date.now() });
```

**Python:**

```python
from carapace_sdk import CarapaceAgent, AriaRegistry

# Create an agent identity
agent = CarapaceAgent.create(
    name="my-lobster",
    capabilities=["email-read", "calendar-write"],
)

# Register with ARIA
registry = AriaRegistry("https://api.relayforge.tools/aria/v1")
registry.register(agent)

# Sign an action
signed = agent.sign({"action": "read-email", "timestamp": time.time()})
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
| v0.2.0 | ✅ Current | Epistemology tracking |
| v0.3.0 | 🔜 Next | Delegation chains (most time-sensitive) |
| v0.4.0 | Planned | Compliance profiles |
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
