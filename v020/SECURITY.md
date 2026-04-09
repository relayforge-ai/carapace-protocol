# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (current) | ✅ Active |
| < 0.1.0 | ❌ No |

We maintain security fixes on the current minor version only. If you are running a pinned older version, update before reporting.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Option 1 — GitHub Security Advisory (preferred)

Open a private advisory directly on this repository:  
`github.com/relayforge/carapace-protocol` → Security → Advisories → New draft advisory

This creates an encrypted, private thread visible only to repository maintainers.

### Option 2 — Email

Send to: **security@relayforge.tools**

Encrypt sensitive reports with our PGP key (published at relayforge.tools/security.asc).

---

## What to Include

A useful report includes:

- **Description** — what the vulnerability is and where it exists
- **Impact** — what an attacker could do if they exploited it
- **Reproduction** — steps to reproduce, or a minimal proof of concept
- **Affected versions** — which SDK versions and/or ARIA registry versions are affected
- **Suggested fix** — optional, but appreciated

You do not need a fully working exploit. A credible description of the issue is enough to begin investigation.

---

## Our Commitments

| Milestone | Target |
|---|---|
| Acknowledge receipt | 48 hours |
| Initial triage (confirmed / needs info / not a vulnerability) | 5 business days |
| Patch development begins (confirmed vulnerabilities) | 10 business days |
| Public disclosure (coordinated with reporter) | 90 days from confirmation, or sooner if patch is ready |

We will not pursue legal action against researchers who report vulnerabilities in good faith and follow this policy.

---

## Severity Classification

We use CVSS 3.1 base scores as a guide, with the following Carapace-specific adjustments:

| Severity | CVSS | Examples in Carapace context |
|---|---|---|
| **Critical** | 9.0–10.0 | Signature forgery; ARIA registry compromise; private key extraction |
| **High** | 7.0–8.9 | Revocation bypass; registry impersonation; capability scope bypass |
| **Medium** | 4.0–6.9 | Information disclosure via ARIA; timing side-channels in verification |
| **Low** | 0.1–3.9 | Non-sensitive information disclosure; minor spec ambiguities |

---

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We confirm and begin investigation within 5 business days
3. We develop and test a fix
4. We notify the reporter before public disclosure
5. We publish a security advisory and release a patched version simultaneously
6. We credit the reporter (unless they prefer anonymity)

If we cannot produce a fix within 90 days, we will publish a mitigation advisory with the known workaround, and note that a full fix is in progress.

---

## Out of Scope

The following are not eligible for security reports under this policy:

- Social engineering of RelayForge employees or contractors
- Physical attacks against RelayForge infrastructure
- Denial of service via volumetric traffic (rate limiting is an operational control, not a code vulnerability)
- Vulnerabilities in third-party dependencies (report to the upstream project; notify us if Carapace is directly affected)
- Issues in user-registered agents in the ARIA registry (report agent-level abuse to abuse@relayforge.tools)

---

## Known Limitations (By Design)

The following behaviors are documented as design limitations, not vulnerabilities. Reports for these will be closed as informational:

- `verify_local()` does not check revocation status (offline by design — see revocation list spec)
- Agent capability declarations are not runtime-enforced by the protocol (enforcement is the host system's responsibility)
- ARIA registry metadata fields outside the signed payload are not agent-signed (they are ARIA-integrity-protected)
- A legitimately registered agent with valid credentials that behaves maliciously is outside Carapace's threat model

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full list of design boundaries.

---

## Hall of Fame

We will publicly credit researchers who responsibly disclose valid vulnerabilities here, with their permission.

*(None yet — be the first.)*

---

## Contact

- Security issues: security@relayforge.tools
- Abuse reports: abuse@relayforge.tools
- General questions: hello@relayforge.tools
- PGP key: https://relayforge.tools/security.asc
