# Carapace Protocol — Threat Model
**Version:** 0.1.0  
**Date:** March 2026  
**Author:** Ryan S. Anderson, RelayForge  
**Status:** Active — updated with each protocol revision

---

## Purpose

This document describes what Carapace protects against, what it explicitly does not protect against, and the residual risks that operators must manage independently. A trust protocol that does not define its own limits is not a trust protocol — it is a false assurance.

This threat model uses a simplified STRIDE framework adapted for agent identity systems.

---

## System Boundary

The Carapace trust envelope covers:

- **Agent registration** — the act of binding an agent's declared identity and capabilities to a cryptographic owner
- **Agent card signing** — Ed25519 signature over the JCS-canonical agent card payload
- **Registry storage** — ARIA's role in indexing, serving, and revoking agent cards
- **Verification** — both registry-based (`verify()`) and offline (`verify_local()`)
- **Discovery** — querying ARIA for agents by capability, framework, or tag

The Carapace trust envelope does **not** cover:

- Agent runtime behavior
- The content of messages an agent sends or receives
- The correctness of an agent's tool implementations
- The security of the host system running the agent
- Network transport (use TLS separately)

---

## Assets Under Protection

| Asset | Value | Protection Mechanism |
|---|---|---|
| Agent identity | Proves who built and owns an agent | Ed25519 OwnerBlock binding |
| Declared capabilities | Prevents capability inflation post-registration | JCS-canonical signature over full card |
| Owner private key | Root of trust for all registrations | Never transmitted; owner-held only |
| ARIA registry integrity | Authoritative source of agent identity | Registry-side signature validation |
| Revocation status | Ability to invalidate compromised agents | Registry status field + revocation list |

---

## Threat Analysis (STRIDE)

### S — Spoofing

**Threat:** An attacker impersonates a registered agent by presenting a fake or copied agent card.

**Carapace mitigation:** Ed25519 signatures bind the card to the owner's private key. A copied card without the private key cannot be re-signed with new content. `verify()` and `verify_local()` both validate the signature against the registered public key.

**Residual risk:** Key compromise. If the owner's private key is stolen, an attacker can register new agents or re-sign altered cards indistinguishably from the legitimate owner. Carapace cannot detect this.

**Operator responsibility:** Secure key storage (HSM, secrets manager, or at minimum environment variables — not hardcoded). Rotate keys and re-register on suspected compromise.

---

### T — Tampering

**Threat:** An attacker modifies an agent card in transit — changing capabilities, endpoints, or owner — to escalate privileges or redirect traffic.

**Carapace mitigation:** JCS canonicalization (RFC 8785) + Ed25519 signing (RFC 8032) over the full card payload. Any single-byte modification to the signed fields invalidates the signature. `verify_local()` catches this with no network call.

**Residual risk:** Fields outside the signed payload (e.g., ARIA-added metadata, timestamps, registry annotations) are not covered by the agent's own signature. These are integrity-protected by ARIA's own infrastructure, not by Carapace cryptography.

**Operator responsibility:** Treat ARIA-side metadata as registry-sourced, not agent-sourced. Do not make trust decisions based on unsigned fields.

---

### R — Repudiation

**Threat:** An agent owner denies having registered an agent or declared specific capabilities.

**Carapace mitigation:** The OwnerBlock cryptographically binds the registration to the owner's public key. Because only the holder of the corresponding private key can produce the signature, non-repudiation holds as long as key integrity holds.

**Residual risk:** Key sharing. If a team shares a private key, individual attribution within that team is not possible. Carapace signs at the key level, not the individual operator level.

**Operator responsibility:** Treat owner keys as individual credentials. One key per operator, not one key per organization.

---

### I — Information Disclosure

**Threat:** Sensitive information leaks through the agent card or registry.

**Carapace mitigation:** Agent cards contain only what the registrant explicitly provides. No credentials, API keys, or system internals are part of the card schema.

**Residual risk:** Capability descriptions are public by design (ARIA is a discovery platform). Detailed capability descriptions could reveal system architecture or internal tooling to adversaries. Agent names and endpoint URLs are also public.

**Operator responsibility:** Do not include sensitive system details in capability descriptions, agent names, or endpoint metadata. Use opaque identifiers where necessary.

---

### D — Denial of Service

**Threat:** ARIA registry is made unavailable, blocking all online verification.

**Carapace mitigation:** `verify_local()` performs full Ed25519 verification with no registry dependency. Systems designed for air-gapped or high-availability environments should cache cards and use offline verification.

**Residual risk:** Revocation status is not available offline. A revoked agent with a cached, previously-valid card will pass `verify_local()`. See Revocation section below.

**Operator responsibility:** Define a cache TTL appropriate to your risk tolerance. Safety-critical systems should use short TTLs or require online verification for high-privilege operations.

---

### E — Elevation of Privilege

**Threat:** A registered agent operates beyond its declared capabilities — accessing systems or performing actions not reflected in its Carapace card.

**Carapace mitigation (v0.1.1):** Capabilities are declared and signed at registration. Post-signing alteration is detectable. However, Carapace v0.1.1 does not enforce runtime capability boundaries — it declares them, and verification confirms the declaration is authentic and unaltered.

**Residual risk (significant):** A legitimately registered agent with accurately declared capabilities can still be programmed to behave maliciously within those boundaries. Carapace verifies the credential, not the behavior. This is the same as a licensed contractor who uses their license to gain access and then acts improperly.

**Operator responsibility:** Capability declarations are a starting point for access control policy, not a replacement for it. Host systems must implement their own enforcement of capability boundaries. The Carapace capability taxonomy (see roadmap) will provide machine-readable scope definitions to make this practical.

---

## What Carapace Explicitly Does Not Protect Against

This list exists so that operators have no false expectations.

| Threat | Why Carapace Does Not Cover It |
|---|---|
| A malicious agent accurately registered | Carapace verifies identity and declared capabilities, not intent or behavior |
| Social engineering of ARIA operators | Registry-side threat; requires ARIA operational security |
| Key compromise after registration | No mechanism to detect stolen private keys in use |
| Agent runtime behavior | Out of scope by design — protocol layer only |
| Prompt injection via agent inputs | Content-layer threat; Carapace does not inspect message content |
| Supply chain attacks on agent dependencies | Framework-level threat; outside protocol scope |
| DNS or BGP hijacking of registry endpoint | Network-layer threat; use TLS and certificate pinning |
| Insider threat at RelayForge | Trust in the registry operator is a requirement; federation mitigates this |

---

## Revocation Limitations

Current revocation (v0.1.1) is soft-delete via ARIA status field. This means:

- Online `verify()` calls will correctly return `verified: false` for revoked agents
- Offline `verify_local()` has **no visibility into revocation status**
- Agents with cached cards will pass offline verification until cache expiry

**Planned mitigation (v0.2.0):** Signed revocation lists at `/aria/v1/revocations`, pulled periodically, enabling offline revocation checks. See the Revocation List specification.

---

## Trust Assumptions

Carapace makes the following explicit trust assumptions. If these do not hold, the security properties do not hold.

1. **The ARIA registry operator (RelayForge) is trusted** not to fabricate or alter agent registrations. Federation (planned) reduces dependency on a single operator.
2. **The owner's private key is held securely** by the registrant. Carapace cannot detect compromised keys.
3. **The host system correctly calls `verify()`** before acting on agent-sourced instructions. Carapace cannot enforce its own use.
4. **TLS is in use** on all connections to ARIA. Carapace does not provide transport security.
5. **Declared capabilities reflect actual capabilities.** Carapace signs the declaration; it cannot audit the implementation.

---

## Residual Risk Summary

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| Private key compromise | Critical | Low (with proper hygiene) | Key rotation policy, secrets management |
| Malicious legitimate agent | High | Medium | Runtime monitoring, capability enforcement by host |
| Offline revocation blindspot | Medium | Low (short TTL) | Cache TTL policy, online verify for high-privilege ops |
| ARIA unavailability | Medium | Low | verify_local() fallback, card caching |
| Capability scope inflation | Medium | Medium | Capability taxonomy (roadmap), host-side enforcement |
| Information disclosure via card | Low | Low | Operator discipline on card content |

---

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1.0 | March 2026 | Initial threat model |

---

*Carapace Protocol Threat Model — RelayForge — Apache 2.0*  
*Feedback and identified gaps: security@relayforge.tools*
