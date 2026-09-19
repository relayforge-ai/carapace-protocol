const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { createReceipt, verifyReceipt, postReceipt } = require('../dist/receipt');
const { enforce, enforceAll, enforceAny, CardExpired } = require('../dist/enforce');
const vector = () => JSON.parse(readFileSync(join(__dirname, '../../test-vectors/receipt-v2.json'), 'utf8'));

test('Python-signed shared vector verifies; Unicode and numeric content hashes agree', async () => {
  const { args, receipt } = vector();
  assert.equal(await verifyReceipt(receipt, receipt.public_key), true);
  assert.equal((await createReceipt(receipt.tool_id, args)).args_hash, receipt.args_hash);
});
for (const [field, value] of Object.entries({
  tool_id:'fixture.delete', agent_id:'other', status:'error', args_hash:'0'.repeat(64),
  result_hash:'1'.repeat(64), receipt_id:'other', issued_at:'2026-01-02T00:00:00Z',
  domain:'other.protocol', receipt_version:'1', tool_version:'2', authorization_id:'other',
  public_key:'2'.repeat(64), call_hash:'3'.repeat(64), signature:'4'.repeat(128),
})) test(`reject changed ${field}`, async () => {
  assert.equal(await verifyReceipt({...vector().receipt, [field]:value}), false);
});
test('legacy and unsigned records do not become authenticated', async () => {
  assert.equal(await verifyReceipt({call_hash:'a'.repeat(64), signature:'b'.repeat(128), public_key:'c'.repeat(64)}), false);
  assert.equal(await verifyReceipt(await createReceipt('fixture.read', {})), false);
});
test('unknown and missing fields fail', async () => {
  const receipt = vector().receipt;
  assert.equal(await verifyReceipt({...receipt, unbound_claim:'approved'}), false);
  delete receipt.tool_version;
  assert.equal(await verifyReceipt(receipt), false);
});

test('inherited receipt fields cannot authenticate unrelated own claims', async () => {
  const signed = vector().receipt;
  const inherited = Object.create(signed);
  for (let i = 0; i < Object.keys(signed).length; i++) inherited[`unbound_${i}`] = 'approved';
  assert.equal(await verifyReceipt(inherited), false);
  // Ordinary JSON envelopes and null-prototype own-field objects still work.
  assert.equal(await verifyReceipt(JSON.parse(JSON.stringify(signed))), true);
  assert.equal(await verifyReceipt(Object.assign(Object.create(null), signed)), true);
});

test('omitted or undefined options serialize as explicit null v2 fields', async () => {
  for (const options of [{}, {agentId:undefined, toolVersion:undefined, authorizationId:undefined}]) {
    const receipt = await createReceipt('fixture.read', {}, null, options);
    const wire = JSON.parse(JSON.stringify(receipt));
    for (const field of ['agent_id', 'tool_version', 'authorization_id']) {
      assert.equal(Object.hasOwn(wire, field), true);
      assert.equal(wire[field], null);
    }
  }
});
test('ambiguous JSON is rejected', async () => {
  for (const value of [NaN, Infinity, 2**53, undefined, {x:'\ud800'}, new Date()]) {
    await assert.rejects(createReceipt('fixture.read', value));
  }
});
test('every enforcement entry point rejects expired/invalid expiry', () => {
  for (const expiry of ['2000-01-01T00:00:00Z', '', 'bad', 0, false, '2099-01-01T00:00:00', '2099-02-30T00:00:00Z']) {
    const card = {capabilities:['read'], expires_at:expiry};
    for (const guard of [c=>enforce(c,'read'),c=>enforceAll(c,['read']),c=>enforceAny(c,['read'])]) {
      assert.throws(()=>guard(card), CardExpired);
    }
  }
});
test('exact expiry is denied; valid offset/future and absent expiry remain usable', () => {
  const previous = Date.now;
  Date.now = () => Date.parse('2026-01-01T00:00:00Z');
  try {
    assert.throws(()=>enforce({capabilities:['read'],expires_at:'2025-12-31T16:00:00-08:00'},'read'),CardExpired);
    enforce({capabilities:['read'],expires_at:'2026-01-01T00:00:01Z'},'read');
    enforce({capabilities:['read']},'read');
    enforce({capabilities:['read'],expires_at:'bad'},'read',{checkExpiry:false});
  } finally { Date.now = previous; }
});
test('upload requires explicit v2 acknowledgement; old servers are detected', async () => {
  const previous = globalThis.fetch;
  try {
    for (const [ack, expected] of [
      [{ok:true},false], [{ok:true,verification_status:'legacy_unverified'},false],
      [{ok:true,verification_status:'verified_v2'},true],
    ]) {
      globalThis.fetch = async () => new Response(JSON.stringify(ack), {status:200});
      assert.equal(await postReceipt('https://example.com',vector().receipt),expected);
    }
  } finally { globalThis.fetch = previous; }
});
