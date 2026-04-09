# Carapace Protocol

[![PyPI version](https://img.shields.io/pypi/v/carapace-sdk?color=C45E2A&label=PyPI)](https://pypi.org/project/carapace-sdk/)
[![npm version](https://img.shields.io/npm/v/@relayforge/carapace-sdk?color=C45E2A&label=npm)](https://www.npmjs.com/package/@relayforge/carapace-sdk)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![NIST NCCoE](https://img.shields.io/badge/NIST%20NCCoE-submitted-lightgrey)](https://relayforge.tools/trust)

**Carapace is an open credentialing protocol for AI agents. Think journeyman card, not password.**

An agent that can authenticate isn't the same as an agent you can trust. Authentication tells you who's knocking. Carapace tells you who built the agent, what it's certified to do, whether it's been tampered with, and who's accountable if it isn't.

```python
import os
from carapace import CarapaceClient

client = CarapaceClient(
    registry_url="https://api.relayforge.tools/aria/v1",
    owner_private_key=os.environ["CARAPACE_OWNER_KEY"]
)
card = client.register(
    name="ResearchAgent",
    description="Searches and summarizes topics",
    framework="langchain",
    capabilities=[{"id": "research", "name": "Research", "description": "Searches and summarizes topics"}],
    endpoints=[{"protocol": "https", "url": "https://my-agent.com/run"}]
)
print(card.id)  # your agent is now in the registry
```

---

## Contents

- [Installation](#installation)
- [Quickstart](#quickstart)
- [Core Concepts](#core-concepts)
- [API Reference](#api-reference)
- [MCP Integration](#mcp-integration)
- [A2A Integration](#a2a-integration)
- [Standards Alignment](#standards-alignment)
- [Contributing](#contributing)

---

## Installation

**Python**
```bash
pip install carapace-sdk
```

**TypeScript / Node**
```bash
npm install @relayforge/carapace-sdk
```

Requires Python 3.9+ or Node 18+. No other runtime dependencies beyond the package.

---

## Quickstart

### 1. Generate a keypair

Your Ed25519 private key signs every agent card you register. Generate one and store it in your environment — it never leaves your process.

```bash
# Python
python -m carapace keygen
# → CARAPACE_OWNER_KEY=a1b2c3d4...  (64-char hex)

# Node
npx carapace-sdk keygen
# → CARAPACE_OWNER_KEY=a1b2c3d4...  (64-char hex)
```

Add to your environment:
```bash
export CARAPACE_OWNER_KEY=a1b2c3d4...
```

### 2. Initialize a client

**Python**
```python
import os
from carapace import CarapaceClient

client = CarapaceClient(
    registry_url="https://api.relayforge.tools/aria/v1",
    owner_private_key=os.environ["CARAPACE_OWNER_KEY"]
)
```

**TypeScript**
```typescript
import { CarapaceClient } from '@relayforge/carapace-sdk';

const client = new CarapaceClient({
  registryUrl: process.env.CARAPACE_REGISTRY_URL
    ?? 'https://api.relayforge.tools/aria/v1',
  ownerKey: process.env.CARAPACE_OWNER_KEY,
});
```

### 3. Register an agent

```python
card = client.register(
    name="ResearchAgent",
    description="Searches and summarizes topics",
    framework="langchain",
    capabilities=[
        {
            "id":          "research",
            "name":        "Research",
            "description": "Searches and summarizes topics"
        }
    ],
    endpoints=[
        {
            "protocol": "https",
            "url":      "https://my-agent.com/run"
        }
    ]
)

print(card.id)                # uuid — your agent's permanent registry ID
print(card.signature)         # Ed25519 hex — tamper-evident proof of registration
print(card.owner.public_key)  # derived public key — safe to share
```

### 4. Verify an agent

Before your system acts on a message from an agent, verify it.

```python
result = client.verify(agent_id="uuid-of-agent")

if result.verified:
    print("Trusted:", result.agent.name)
else:
    print("Rejected:", result.reason)
```

**Offline verification** — no registry call required:
```python
ok = client.verify_local(
    card=card,
    signature=card.signature,
    public_key=card.owner.public_key
)
```

### 5. Discover agents

```python
# By capability
agents = client.discover(capability="research")

# By framework
agents = client.discover(framework="langchain")

# Full-text + limit
agents = client.discover(text="summarize documents", limit=10)
```

---

## Core Concepts

### Agent Cards

An Agent Card is a signed JSON document that describes an agent: who owns it, what it can do, and how to reach it. Cards are built at registration, signed with your Ed25519 private key, and stored in the ARIA registry. The card is the credential — it travels with the agent.

```json
{
  "id": "a3f7...",
  "name": "ResearchAgent",
  "description": "Searches and summarizes topics",
  "framework": "langchain",
  "capabilities": [
    { "id": "research", "name": "Research", "description": "..." }
  ],
  "endpoints": [
    { "protocol": "https", "url": "https://my-agent.com/run" }
  ],
  "owner": {
    "public_key": "b9e2..."
  },
  "signature": "7f3a...",
  "status": "active"
}
```

### Signatures

Every card is signed using Ed25519 (FIPS 186-5 / RFC 8032) over a JCS-canonical (RFC 8785) representation of the payload. JCS canonicalization means the signature is stable regardless of key ordering or whitespace variation in the JSON.

What this guarantees:

- **Tamper evidence** — any modification to the card after signing invalidates the signature
- **Owner binding** — only the holder of the private key could have produced the signature
- **Offline verifiability** — verification requires only the card, the signature, and the public key

The private key never leaves your process. The public key is stored in ARIA. Revocation is handled by the registry (status: `"revoked"`) — revoked cards fail `verify()` but remain in the registry for audit purposes.

### ARIA Registry

ARIA (Agent Registry & Identity Authority) is the hosted registry at `https://api.relayforge.tools/aria/v1`. It is a live endpoint, not a dashboard.

What ARIA does:

- Stores and indexes Agent Cards
- Serves verification requests
- Supports independent evaluator attestations (signed objects appended to cards by third parties)
- Returns MCP `tools/list` and A2A `/.well-known/agent.json` manifests on request

ARIA is queried at runtime by agents and host systems. It is developer-accessible with no enterprise gating.

Self-hosting is supported — point `registry_url` at your own ARIA-compatible endpoint.

---

## API Reference

### `CarapaceClient`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `registry_url` | `str` | Yes | ARIA endpoint. Override with `CARAPACE_REGISTRY_URL`. |
| `owner_private_key` | `str` (hex) | Yes | 64-char hex Ed25519 private key. Set via `CARAPACE_OWNER_KEY`. |

### `client.register()`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | `str` | Yes | Agent name. |
| `description` | `str` | Yes | What the agent does. |
| `framework` | `str` | Yes | e.g. `langchain`, `autogen`, `custom` |
| `capabilities` | `list[Capability]` | Yes | Capability objects (see below). |
| `endpoints` | `list[Endpoint]` | Yes | Endpoint objects (see below). |
| `version` | `str` | No | Semver string. |
| `tags` | `list[str]` | No | Searchable tags. |
| `metadata` | `dict` | No | Arbitrary key-value pairs. |

Returns `AgentCard`.

**Capability object**

| Field | Type | Required |
|---|---|---|
| `id` | `str` | Yes |
| `name` | `str` | Yes |
| `description` | `str` | Yes |

**Endpoint object**

| Field | Type | Required |
|---|---|---|
| `protocol` | `str` | Yes — `https`, `a2a`, `mcp` |
| `url` | `str` | Yes |

### `client.verify(agent_id)`

Returns `VerifyResult`.

| Field | Type | Description |
|---|---|---|
| `.verified` | `bool` | `True` if signature valid and agent is active. |
| `.reason` | `str \| None` | Failure reason. `None` on success. |
| `.agent` | `AgentCard \| None` | Full card if verified. |

### `client.verify_local(card, signature, public_key)`

Ed25519 verification with no network call. Returns `bool`.

### `client.discover(filters)`

| Parameter | Type | Description |
|---|---|---|
| `capability` | `str` | Filter by capability id. |
| `framework` | `str` | Filter by framework. |
| `tag` | `str` | Filter by tag. |
| `text` | `str` | Full-text search. |
| `limit` | `int` | Max results. Default: `20`. |

Returns `list[AgentCard]`.

### `client.get(agent_id)`

Fetch a card by UUID. Returns `AgentCard`.

### `client.public_key()`

Return the hex-encoded public key derived from your owner key. Returns `str`.

---

## MCP Integration

Wrap your MCP server to verify caller identity on every tool invocation. Unverified callers are rejected before your handlers run.

**Python**
```python
from carapace.integrations.mcp import CarapaceMiddleware
from mcp.server import Server

server = Server("my-mcp-server")
server = CarapaceMiddleware(
    server,
    client=client,
    agent_id="uuid-of-registered-agent"
)
```

**TypeScript**
```typescript
import { carapaceMcp } from '@relayforge/carapace-sdk/mcp';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'my-mcp-server', version: '1.0.0' });
const secureServer = carapaceMcp(server, {
  client,
  agentId: 'uuid-of-registered-agent',
});
```

`CarapaceMiddleware` / `carapaceMcp`:
- Verifies caller identity against ARIA on each tool call
- Attaches trust context to tool call metadata
- Rejects unverified callers before your handlers execute

Export your card as an MCP `tools/list`:
```python
from carapace import generate_tools_list
tools = generate_tools_list(card)
```

---

## A2A Integration

Mount a verified A2A agent on your existing web framework. Carapace handles the `/.well-known/agent.json` endpoint and caller verification.

**Python (FastAPI)**
```python
from carapace.integrations.a2a import A2ACarapaceAgent
from fastapi import FastAPI

app = FastAPI()
agent = A2ACarapaceAgent(
    client=client,
    agent_id="uuid-of-registered-agent",
    app=app
)

# Auto-mounted:
# GET  /.well-known/agent.json  →  A2A agent card
# POST /run                     →  verified task endpoint
```

**TypeScript (Express)**
```typescript
import { CarapaceA2AAgent } from '@relayforge/carapace-sdk/a2a';
import express from 'express';

const app = express();
const agent = new CarapaceA2AAgent({
  client,
  agentId: 'uuid-of-registered-agent',
  app,
});

// Auto-mounted:
// GET  /.well-known/agent.json  →  A2A agent card
// POST /run                     →  verified task endpoint
```

Generate an A2A card directly:
```python
from carapace import generate_well_known_card
a2a_card = generate_well_known_card(card)
# serve at /.well-known/agent.json
```

---

## Standards Alignment

| Standard | Alignment |
|---|---|
| Ed25519 | FIPS 186-5, RFC 8032 |
| JSON Canonicalization | RFC 8785 (JCS) |
| NIST AI RMF 1.0 | GOVERN, MANAGE, MAP, MEASURE |
| ISA/IEC 62443 | Industrial cybersecurity |
| A2A Protocol | Native manifest output |
| MCP Protocol | Native tools/list output |

Carapace was submitted to NIST NCCoE for standards consideration in March 2026. The technical addendum mapping the protocol to NIST AI RMF 1.0 is available at [relayforge.tools/trust](https://relayforge.tools/trust).

The design intent: a trust envelope that works across every agent protocol stack — MCP for tool access, A2A for agent routing, and whatever comes next. Carapace is the identity layer underneath all of them.

---

## Security Model

- **Private key isolation** — the owner private key is used locally to sign payloads and never transmitted
- **Tamper evidence** — Ed25519 over JCS-canonical JSON; any post-signing modification invalidates the signature
- **Revocation** — soft-delete via ARIA (`status: "revoked"`); cards remain in registry for audit
- **Offline verification** — `verify_local()` requires no network; suitable for air-gapped environments
- **Cross-language consistency** — JS and Python produce byte-identical signatures; verified in CI

To report a vulnerability: open a security advisory on this repository or email security@relayforge.tools.

---

## Contributing

```bash
git clone https://github.com/relayforge/carapace-protocol
cd carapace-protocol

# Python
pip install -e ".[dev]"
pytest

# TypeScript
npm install
npm test
```

Tests run offline — no registry connection required for the test suite.

Before opening a PR:
- All existing tests must pass
- New functionality needs test coverage
- If you're changing the signing or canonicalization logic, add a cross-language interop test

Open an issue before starting large changes. The core signing spec (Ed25519 + JCS) is stable and intentionally not up for redesign — if you have a standards-level objection, file it as an issue with a reference to the relevant RFC or NIST document.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

Built by [RelayForge](https://relayforge.tools). Trust infrastructure for the agentic web.

[relayforge.tools/trust](https://relayforge.tools/trust) · [ARIA Registry](https://api.relayforge.tools/aria/v1) · [PyPI](https://pypi.org/project/carapace-sdk/) · [npm](https://www.npmjs.com/package/@relayforge/carapace-sdk)
