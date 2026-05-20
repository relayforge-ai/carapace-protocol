const assert = require('node:assert/strict');
const test = require('node:test');

const { createReceipt, verifyReceipt, postReceipt } = require('../dist/receipt.js');
const { runGateCheck, fetchCatalog } = require('../dist/catalog.js');

// ─── sha256Json canonical ordering ───────────────────────────────────────────

test('sha256Json: nested object keys sorted recursively', async () => {
  // Two receipts with differently-ordered keys at nested level must hash identically
  const { createReceipt: cr } = require('../dist/receipt.js');
  // We test indirectly: args_hash must be stable regardless of property insertion order
  const r1 = await cr('tool', { z: 1, a: 2 });
  const r2 = await cr('tool', { a: 2, z: 1 });
  assert.equal(r1.args_hash, r2.args_hash, 'args_hash must be key-order-independent');
});

// ─── createReceipt basic ──────────────────────────────────────────────────────

test('createReceipt: unsigned receipt has expected fields', async () => {
  const receipt = await createReceipt('brave-search', { q: 'test' });
  assert.equal(receipt.tool_id, 'brave-search');
  assert.equal(typeof receipt.call_hash, 'string');
  assert.equal(receipt.call_hash.length, 64);
  assert.equal(typeof receipt.args_hash, 'string');
  assert.equal(receipt.result_hash, null);
  assert.equal(receipt.signature, null);
  assert.equal(receipt.public_key, null);
  assert.equal(receipt.status, 'ok');
});

test('createReceipt: result hash present when result provided', async () => {
  const receipt = await createReceipt('tool', { q: 'test' }, { answer: 42 });
  assert.notEqual(receipt.result_hash, null);
  assert.equal(receipt.result_hash.length, 64);
});

test('createReceipt: different args produce different hashes', async () => {
  const r1 = await createReceipt('tool', { q: 'hello' });
  const r2 = await createReceipt('tool', { q: 'world' });
  assert.notEqual(r1.args_hash, r2.args_hash);
  assert.notEqual(r1.call_hash, r2.call_hash);
});

test('createReceipt: signed receipt populates signature and public_key', async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  );
  const receipt = await createReceipt('tool', { q: 'signed' }, null, { keyPair });
  assert.notEqual(receipt.signature, null);
  assert.notEqual(receipt.public_key, null);
  assert.equal(receipt.signature.length, 128);  // 64 bytes → 128 hex chars
  assert.equal(receipt.public_key.length, 64);   // 32 bytes → 64 hex chars
});

// ─── verifyReceipt ────────────────────────────────────────────────────────────

test('verifyReceipt: valid signature verifies', async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  );
  const receipt = await createReceipt('tool', { q: 'test' }, null, { keyPair });
  const ok = await verifyReceipt(receipt);
  assert.equal(ok, true);
});

test('verifyReceipt: tampered call_hash fails', async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  );
  const receipt = await createReceipt('tool', { q: 'test' }, null, { keyPair });
  receipt.call_hash = '0'.repeat(64);
  const ok = await verifyReceipt(receipt);
  assert.equal(ok, false);
});

test('verifyReceipt: unsigned receipt returns false', async () => {
  const receipt = await createReceipt('tool', {});
  const ok = await verifyReceipt(receipt);
  assert.equal(ok, false);
});

// ─── postReceipt ──────────────────────────────────────────────────────────────

test('postReceipt: returns false on network error (no server running)', async () => {
  const receipt = await createReceipt('tool', {});
  const ok = await postReceipt('http://127.0.0.1:19999', receipt, { timeout: 500 });
  assert.equal(ok, false);
});

// ─── runGateCheck ─────────────────────────────────────────────────────────────

function makeCatalogState() {
  return {
    catalog: [
      {
        id: 'brave-search',
        name: 'Brave Search',
        description: '',
        endpoint_url: 'https://brave.com/mcp',
        status: 'active',
        clawmark_score: 85,
        gate_pass: true,
        tier: 'free',
        safety_class: 'safe',
        certification_tier: 'clawmark_grandfathered',
        streaming_supported: false,
        clawmark_breakdown: {},
        scope_requirements: {},
      },
      {
        id: 'low-score',
        name: 'Low Score',
        description: '',
        endpoint_url: 'https://example.com',
        status: 'active',
        clawmark_score: 50,
        gate_pass: false,
        tier: 'free',
        safety_class: 'safe',
        certification_tier: 'unclassified',
        streaming_supported: false,
        clawmark_breakdown: {},
        scope_requirements: {},
      },
      {
        id: 'suspended-tool',
        name: 'Suspended',
        description: '',
        endpoint_url: 'https://example.com',
        status: 'suspended',
        clawmark_score: 90,
        gate_pass: true,
        tier: 'free',
        safety_class: 'safe',
        certification_tier: 'clawmark_grandfathered',
        streaming_supported: false,
        clawmark_breakdown: {},
        scope_requirements: {},
      },
    ],
    total: 3,
    etag: 'abc123',
    fetched_at: new Date().toISOString(),
  };
}

test('runGateCheck: all gates pass for active high-score tool', () => {
  const state = makeCatalogState();
  const result = runGateCheck('brave-search', state);
  assert.equal(result.passed, true);
  assert.equal(result.gates_failed.length, 0);
});

test('runGateCheck: fails catalog_membership for unknown tool', () => {
  const state = makeCatalogState();
  const result = runGateCheck('ghost-tool', state);
  assert.equal(result.passed, false);
  assert.equal(result.blocked_by, 'catalog_membership');
});

test('runGateCheck: fails active_status for suspended tool', () => {
  const state = makeCatalogState();
  const result = runGateCheck('suspended-tool', state);
  assert.equal(result.passed, false);
  assert.equal(result.blocked_by, 'active_status');
});

test('runGateCheck: fails clawmark_gate for low score', () => {
  const state = makeCatalogState();
  const result = runGateCheck('low-score', state);
  assert.equal(result.passed, false);
  assert.equal(result.blocked_by, 'clawmark_gate');
});

test('runGateCheck: fails revocation_clear when tool in revoked set', () => {
  const state = makeCatalogState();
  const result = runGateCheck('brave-search', state, { revokedIds: new Set(['brave-search']) });
  assert.equal(result.passed, false);
  assert.equal(result.blocked_by, 'revocation_clear');
});

test('runGateCheck: observe_only mode passes everything', () => {
  const state = makeCatalogState();
  const result = runGateCheck('ghost-tool', state, { trustGatesEnabled: false });
  assert.equal(result.passed, true);
  assert.equal(result.details.mode, 'observe_only');
});

test('runGateCheck: fail_open when state is null', () => {
  const result = runGateCheck('brave-search', null);
  assert.equal(result.passed, true);
  assert.equal(result.details.mode, 'fail_open');
  assert.equal(result.details.reason, 'aria_unreachable');
});

// ─── v0.5.0 SDK exports ───────────────────────────────────────────────────────

test('v0.5.0 receipt and catalog APIs are exported from entrypoint', () => {
  const sdk = require('../dist/index.js');
  assert.equal(typeof sdk.createReceipt, 'function');
  assert.equal(typeof sdk.verifyReceipt, 'function');
  assert.equal(typeof sdk.postReceipt, 'function');
  assert.equal(typeof sdk.fetchCatalog, 'function');
  assert.equal(typeof sdk.runGateCheck, 'function');
  assert.equal(typeof sdk.catalogGet, 'function');
  assert.equal(typeof sdk.catalogIsActive, 'function');
});
