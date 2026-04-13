# Carapace Protocol — Independent Implementation Specification
**Version:** 0.1.1  
**Purpose:** Everything a team needs to implement Carapace independently — without using the RelayForge SDK — and produce byte-identical results.

A standard with one implementation is a library. Two independent, interoperable implementations is a protocol. This document exists to make that second implementation as easy as possible.

---

## What "Independent Implementation" Means

Your implementation is independent if:

1. You wrote it from this spec, not by reading the RelayForge SDK source
2. Your signed agent cards verify correctly against the RelayForge SDK (`verify_local()` returns `true`)
3. Cards signed by the RelayForge SDK verify correctly against your implementation
4. You publish your implementation publicly with a statement of interoperability

Language does not matter. Go, Rust, Java, C#, Ruby — any language with an Ed25519 library and JSON support can implement this spec.

---

## Cryptographic Primitives

### Key Generation

Generate an Ed25519 keypair (RFC 8032).

- Private key: 32 bytes (256 bits)
- Public key: 32 bytes, derived from private key
- Representation: lowercase hex encoding, 64 characters each

```
private_key_hex = bytes_to_hex(ed25519_generate_private_key())  # 64 chars
public_key_hex  = bytes_to_hex(ed25519_get_public_key(private))  # 64 chars
```

**Reference libraries by language:**

| Language | Library |
|---|---|
| Python | `PyNaCl` (`nacl.signing.SigningKey`) |
| JavaScript/TypeScript | `@noble/ed25519` v2 |
| Go | `crypto/ed25519` (stdlib) |
| Rust | `ed25519-dalek` |
| Java | `Bouncy Castle` |
| C# | `NSec.Cryptography` |

---

## Canonicalization

Before signing, the agent card payload must be canonicalized using JCS (JSON Canonicalization Scheme, RFC 8785).

JCS rules:
1. All keys sorted lexicographically (Unicode code point order)
2. No whitespace (no spaces, no newlines)
3. UTF-8 encoding
4. Numbers in IEEE 754 representation
5. Strings escaped per JSON spec

**Test vector — canonicalization:**

Input (arbitrary key order):
```json
{"z": 1, "a": "hello", "m": [3, 1, 2]}
```

Canonical output (must match exactly, byte-for-byte):
```
{"a":"hello","m":[3,1,2],"z":1}
```

---

## Agent Card Schema

The minimal signable agent card payload:

```json
{
  "capabilities": [
    {
      "description": "string",
      "id": "string",
      "name": "string"
    }
  ],
  "description": "string",
  "endpoints": [
    {
      "protocol": "string",
      "url": "string"
    }
  ],
  "framework": "string",
  "name": "string",
  "owner": {
    "public_key": "string (hex)"
  }
}
```

**Key ordering for canonicalization (top-level):**

`capabilities`, `description`, `endpoints`, `framework`, `name`, `owner`

Within `capabilities` objects: `description`, `id`, `name`  
Within `endpoints` objects: `protocol`, `url`  
Within `owner` object: `public_key`

**Important:** Arrays preserve insertion order. Only object keys are sorted.

---

## Signing

1. Build the agent card object with required fields
2. Canonicalize using JCS (RFC 8785)
3. Sign the canonical UTF-8 bytes using Ed25519 (RFC 8032)
4. Encode signature as lowercase hex (128 characters)

```python
# Pseudocode
payload = build_agent_card(name, description, framework, capabilities, endpoints, owner_public_key)
canonical = jcs_canonicalize(payload)        # deterministic UTF-8 bytes
signature  = ed25519_sign(canonical, private_key)
signature_hex = bytes_to_hex(signature)      # 128 chars
```

---

## Test Vectors

Use these to verify your implementation produces byte-identical results.

### Test Vector 1 — Minimal Card

**Private key (hex):**
```
0000000000000000000000000000000000000000000000000000000000000001
```
*(This is a test-only key. Never use in production.)*

**Input card object:**
```json
{
  "name": "TestAgent",
  "description": "A test agent",
  "framework": "custom",
  "capabilities": [{"id": "test", "name": "Test", "description": "Testing"}],
  "endpoints": [{"protocol": "https", "url": "https://example.com"}],
  "owner": {"public_key": "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"}
}
```

**Expected canonical JSON (UTF-8 bytes, no trailing newline):**
```
{"capabilities":[{"description":"Testing","id":"test","name":"Test"}],"description":"A test agent","endpoints":[{"protocol":"https","url":"https://example.com"}],"framework":"custom","name":"TestAgent","owner":{"public_key":"4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"}}
```

**Expected signature (hex):**
```
[Generate by running: python -m carapace test-vector 1]
```

*(Full pre-computed test vector signatures will be published at relayforge.tools/docs/test-vectors once the reference implementation stabilizes. Submit a PR with your language's results to validate interoperability.)*

---

## Verification

To verify a signed card:

1. Reconstruct the card object (exclude the `signature` field)
2. Canonicalize using JCS
3. Verify the Ed25519 signature against the owner's public key

```python
# Pseudocode
card_without_sig = remove_field(card, "signature")
canonical = jcs_canonicalize(card_without_sig)
valid = ed25519_verify(canonical, signature_bytes, public_key_bytes)
```

---

## ARIA Registry API (for implementers who want to connect)

**Base URL:** `https://api.relayforge.tools/aria/v1`

| Endpoint | Method | Description |
|---|---|---|
| `/agents` | POST | Register a new agent card |
| `/agents/{id}` | GET | Fetch an agent card by ID |
| `/agents/{id}/verify` | GET | Registry-side verification |
| `/agents` | GET | Discover agents (filters: capability, framework, tag, text) |
| `/revocations` | GET | Signed revocation list |
| `/revocations/{id}` | GET | Single-agent revocation check |
| `/health` | GET | Registry health (returns `{"status":"ok","crypto":true}`) |

Full OpenAPI spec: `https://api.relayforge.tools/aria/v1/openapi.json`

---

## Submitting Your Implementation

Once you have a working implementation:

1. Open an issue at `github.com/relayforge/carapace-protocol` with the title `[Implementer] <Language> — <Your Org>`
2. Include: language, library used for Ed25519, link to your source
3. Run the interoperability test (instructions in `tests/interop/`) and include your output
4. We will add you to the implementations registry and the README

You don't need to be done. A partial implementation that passes the signing test vector is enough to start the conversation.

---

## Why This Matters

Two independent, interoperable implementations turns Carapace from a RelayForge SDK into a protocol. NIST and ISA standards reviews look for this specifically. If your organization is considering Carapace for agent infrastructure, an independent implementation in your primary language is both a contribution to the standard and a hedge against SDK dependency.

Questions: hello@relayforge.tools or open an issue.
