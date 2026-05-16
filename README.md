# Carapace Protocol

[![PyPI version](https://img.shields.io/pypi/v/carapace-sdk?color=C45E2A&label=PyPI)](https://pypi.org/project/carapace-sdk/)
[![npm version](https://img.shields.io/npm/v/%40carapace%2Fsdk?color=C45E2A&label=npm)](https://www.npmjs.com/package/@carapace/sdk)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Carapace is RelayForge's portable trust envelope for AI agents. V0.4 keeps the V0.2/V0.3 runtime controls and adds the V0.4 trust stack:

- runtime capability enforcement, card expiry, versioning, and delegation chains
- local epistemic provenance logs owned by the operator
- compliance profile evaluation in the SDK
- human approval escalation checks in the SDK

ARIA is the registry side of the stack. It stores agent cards, grants, compliance profiles, and escalation records. Epistemic logs are intentionally not stored in ARIA; they remain local operator-owned provenance artifacts.

## Packages

Python:

```bash
pip install carapace-sdk
```

TypeScript:

```bash
npm install @carapace/sdk
```

The current SDK packages expose library functions and data structures. Registry client helpers and CLIs are not part of this package surface.

## Python Quickstart

```python
from carapace import (
    BUILTIN_PROFILES,
    INDUSTRIAL_ESCALATION_POLICY,
    EpistemicLog,
    Source,
    check_escalation,
    enforce,
    evaluate_compliance,
    hash_data,
    make_expires_at,
)

card = {
    "id": "agent-123",
    "capabilities": [
        {"id": "carapace:read:database", "name": "Read database"},
    ],
    "expires_at": make_expires_at(ttl_hours=12),
    "card_version": 2,
    "framework": "custom",
}

enforce(card, "carapace:read:database")

log = EpistemicLog(agent_id=card["id"])
log.record(
    action="classified_record",
    sources=[Source(agent_id="extractor", data_hash=hash_data("source payload"))],
    confidence=0.87,
    reasoning="Matched an approved extraction rule.",
)
assert log.verify_integrity()[0] is True

profile = BUILTIN_PROFILES["carapace-profile:general-saas"]
compliance = evaluate_compliance(card, profile)

escalation = check_escalation(
    policy=INDUSTRIAL_ESCALATION_POLICY,
    requested_capabilities=["carapace:execute:process_control"],
    agent_id=card["id"],
    context="Attempting a protected process-control action.",
)
if escalation:
    print(escalation.to_webhook_payload())
```

## TypeScript Quickstart

```ts
import {
  BUILTIN_PROFILES,
  EpistemicLog,
  INDUSTRIAL_ESCALATION_POLICY,
  checkEscalation,
  enforce,
  evaluateCompliance,
  hashData,
  makeExpiresAt,
} from '@carapace/sdk';

const card = {
  id: 'agent-123',
  capabilities: [{ id: 'carapace:read:database', name: 'Read database' }],
  expires_at: makeExpiresAt({ ttlHours: 12 }),
  card_version: 2,
  framework: 'custom',
};

enforce(card, 'carapace:read:database');

const log = new EpistemicLog('agent-123');
await log.record({
  action: 'classified_record',
  sources: [{ agent_id: 'extractor', data_hash: await hashData('source payload') }],
  confidence: 0.87,
  reasoning: 'Matched an approved extraction rule.',
});

const profile = BUILTIN_PROFILES['carapace-profile:general-saas'];
const compliance = evaluateCompliance(card, profile);

const escalation = checkEscalation(
  INDUSTRIAL_ESCALATION_POLICY,
  ['carapace:execute:process_control'],
  'agent-123',
  'Attempting a protected process-control action.',
);
```

## V0.4 Modules

### Enforcement

Use `enforce`, `enforce_all` / `enforceAll`, `enforce_any` / `enforceAny`, and `has_capability` / `hasCapability` before tool execution. Capability extraction accepts list, string, dict, and dict-form capability collections so V0.2/V0.3 callers keep working.

### Expiry

Use `make_expires_at` / `makeExpiresAt`, `check_expiry` / `checkExpiry`, `is_expired` / `isExpired`, and `time_remaining` / `timeRemaining` to enforce card TTLs and no-immortal-card policy.

### Versioning

Use the version-chain helpers to validate successor relationships, owner continuity, and supersedes registration.

### Delegation

Use `create_delegation`, `verify_delegation`, `verify_delegation_chain`, `enforce_delegated`, and `redelegate` for signed agent-to-agent scoped delegation. Replay protection and TTL checks remain part of the V0.3 behavior.

### Epistemic Tracking

`EpistemicLog` is an append-only hash chain for local provenance. Each entry records the acting agent, action, sources, confidence, reasoning, optional delegation ID, and hashes. Operators can call `verify_integrity()`, `export_audit_trail()`, `export_json()`, and `query(...)`.

ARIA does not store these logs in V0.4.

### Compliance Profiles

`ComplianceProfile` defines named policy bundles. `evaluate_compliance(...)` returns a `ComplianceResult` with blocking violations and warnings.

Built-in V0.4 profiles:

- `carapace-profile:isa-62443`
- `carapace-profile:hipaa`
- `carapace-profile:fedramp-moderate`
- `carapace-profile:nerc-cip`
- `carapace-profile:general-saas`

The profile model includes a `require_legal_entity` field as a forward-compatible policy hook. Legal entity binding is not a shipped V0.4 verifier; profiles that require it produce a warning.

### Escalation

`EscalationPolicy` and `EscalationTrigger` define when human approval is needed. A trigger may match a single capability, a wildcard capability, a capability combination, or a local predicate. `check_escalation(...)` returns the first matching `EscalationRequest`; `check_all_escalations(...)` returns all matches.

`EscalationRequest.to_webhook_payload()` emits the V0.4 webhook shape for approval systems. ARIA is responsible for storing escalation records and approval/denial status.

## ARIA Registry Contract

The companion `aria-registry` service is responsible for registry persistence and public trust surfaces. In V0.4 it supports:

- agent cards, card history, usage, heartbeat, tools, grants, and scoped API keys
- compliance profile storage and retrieval
- escalation creation, approval, denial, and status lookup
- trust pages that present compliance posture, escalation state, local epistemic provenance, and Clawmark evidence

Epistemic logs remain local to the SDK operator by design.

## Development

Python:

```bash
cd python
pip install -e ".[dev]"
pytest
```

TypeScript:

```bash
cd typescript
npm install
npm run build
npm test
```

Root-level package files mirror the Python package for local workspace compatibility. Keep both Python package layouts and the TypeScript entrypoint in sync when changing public APIs.

## Version Notes

Current release: `0.4.0`.

V0.5 concepts such as legal entity binding, cryptographic audit logs, and browser verification are prepared only as internal extension seams. They are not public V0.4 endpoints or shipped product claims.

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [RelayForge](https://relayforge.tools). Trust infrastructure for the agentic web.
