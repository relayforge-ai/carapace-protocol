const assert = require('node:assert/strict');
const test = require('node:test');

const sdk = require('../dist/index.js');

test('V0.4 APIs are exported from the package entrypoint', async () => {
  assert.equal(typeof sdk.EpistemicLog, 'function');
  assert.equal(typeof sdk.hashData, 'function');
  assert.equal(typeof sdk.evaluateCompliance, 'function');
  assert.equal(typeof sdk.checkEscalation, 'function');
  assert.equal(typeof sdk.GENESIS_HASH, 'string');
  assert.equal(sdk.GENESIS_HASH.length, 64);

  const card = {
    id: 'agent-1',
    capabilities: [{ id: 'carapace:read:email' }],
    expires_at: sdk.makeExpiresAt({ ttlHours: 12 }),
    card_version: 2,
    framework: 'custom',
  };

  const profile = sdk.BUILTIN_PROFILES['carapace-profile:general-saas'];
  const compliance = sdk.evaluateCompliance(card, profile);
  assert.equal(compliance.compliant, true);

  const futureProfile = {
    name: 'future-hook',
    requireLegalEntity: true,
  };
  const futureResult = sdk.evaluateCompliance(card, futureProfile);
  assert.equal(futureResult.compliant, true);
  assert.equal(futureResult.warnings[0].rule, 'require_legal_entity');

  const request = sdk.checkEscalation(
    sdk.INDUSTRIAL_ESCALATION_POLICY,
    ['carapace:execute:process_control'],
    'agent-1',
    'protected process-control action',
  );
  assert.equal(request.status, sdk.EscalationStatus.PENDING);
  assert.equal(request.urgency, sdk.EscalationUrgency.CRITICAL);

  const log = new sdk.EpistemicLog('agent-1');
  await log.record({
    action: 'checked_policy',
    sources: [{ agent_id: 'agent-source', data_hash: await sdk.hashData('payload') }],
    confidence: 0.9,
  });
  assert.deepEqual(await log.verifyIntegrity(), { valid: true, brokenAt: null });

  log._entries[0].action = 'tampered';
  assert.deepEqual(await log.verifyIntegrity(), { valid: false, brokenAt: 1 });
});
