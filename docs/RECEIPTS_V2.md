# Carapace 0.5.1 corrective release

Deploy ARIA 0.5.1 **before** upgrading receipt producers. Both existing package
names remain `carapace-sdk`. This release does not change action permissions,
catalog outage policy, or require cloud access for local work.

## Security corrections

`enforce`, `enforce_all`/`enforceAll`, and `enforce_any`/`enforceAny` now reject
expired dictionary cards, malformed expiry, timezone-free expiry and the exact
expiry boundary. Python also accepts timezone-aware datetime objects. Absent/null
expiry remains compatible; hosts requiring a TTL must enforce that policy.
`check_expiry=False` / `checkExpiry:false` is an explicit opt-out, not a safe default.
Capability checks do not verify signatures or grant human authorization.

Newly created receipts use wire version `"2"`. Their `call_hash` is SHA-256 of
the RFC 8785 canonical JSON object containing exactly these fields:

```
receipt_version, domain, receipt_id, issued_at, tool_id, tool_version,
agent_id, authorization_id, args_hash, result_hash, status, public_key
```

The domain is `carapace.tool-receipt.v2`. Ed25519 signs the ASCII lowercase
hexadecimal `call_hash`. `signature` and `call_hash` are the only additional
envelope fields. Optional values are explicit JSON nulls, not omitted fields.
The wire envelope contains only strings/nulls. The content commitments use
RFC 8785 too: JSON-only values, valid Unicode, finite numbers, and safe integers
(absolute value at most 2^53-1). Represent larger exact numbers as strings.
Implicit object-to-string conversions are rejected. Shared Unicode/numeric
vectors live in `test-vectors/receipt-v2.json`.

`tool_version` and `authorization_id` are optional identifiers, not credentials.
No grant is created or independently validated merely by naming one. A signed
receipt authenticates the signer's report; it does not prove execution, result
accuracy, safety, or authorization. With no trusted key argument, SDK verification
establishes possession of the embedded key only. Pin a trusted public key to verify
issuer identity.

## Compatibility and migration

- Legacy receipts remain readable and ingestible in ARIA as `legacy_unverified`.
  SDK verification returns false for them even if their old hash signature is
  intact: that signature does not bind the action metadata. Never re-sign old
  records to manufacture stronger historical evidence.
- New unsigned records are `unsigned_v2`, never `verified_v2`.
- Signed v2 records require an agent ID and its current registered public key in
  ARIA. Locked-out agents and different/unregistered keys are rejected. Old-key
  uploads after rotation are rejected; already stored evidence retains its
  ingestion-time verification status. Preserve its original signature and key.
- Agent-scoped API keys cannot submit another agent's records. For old records
  omitting an agent ID, ARIA attributes them to the authenticated caller. Signed
  v2 envelopes are never rewritten.
- New SDK upload helpers return false when an old server fails to acknowledge
  v2 verification status, even if its HTTP response was successful. Retain the
  local receipt and retry it after upgrading the server. Do not retry the action.
- ARIA exposes the original v2 envelope in each listed record's `receipt` field;
  server ID/time and `verification_status` are separate. Verify that nested
  envelope, not the whole server row.
- Retry the **same** created receipt. ARIA deduplicates `(agent_id, receipt_id)`
  atomically, returning the original server ID. Reuse with different evidence
  returns 409. Creating a new receipt produces a new ID and is not a retry.

Content hashes avoid storing raw arguments/results in receipts, but are not
anonymization: low-entropy values can be guessed. IDs, tool names, hashes and
times are retained metadata. Follow the registry's access/retention policy;
never put secrets in identifier fields. Background upload remains best effort
and is not a durable outbox.

## Release and rollback

1. Apply ARIA's additive migration and test legacy/v2 ingestion in isolation.
2. Deploy ARIA and verify health advertises `receipt_formats: ["1", "2"]` and
   `receipt_verification: "v2_envelope_and_registered_signer"`.
3. Publish the tested SDK tag; upgrade consumers deliberately. The separate
   lobster runtime receipt builder remains legacy/unsigned until migrated.
4. Keep old DB columns/data. A server rollback leaves new columns intact but
   cannot acknowledge v2; upgraded producers report upload failure. Do not
   present an old server or SDK as providing v2 verification.

The receipt format is versioned separately from the SDK patch version. This is
a security tightening: callers relying on malformed dates or legacy receipts
verifying as fully authenticated must change. No universal safety claim is made.
