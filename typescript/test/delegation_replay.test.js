const assert = require('node:assert/strict');
const test = require('node:test');

const {
  InMemoryNonceRegistry,
  createDelegation,
  verifyDelegation,
  verifyDelegationChain,
} = require('../dist/delegation.js');
const {
  extractCapabilityIds,
  hasCapability,
} = require('../dist/enforce.js');

function makeCard() {
  return {
    id: 'agent-a',
    capabilities: [{ id: 'carapace:read:email' }],
    owner: { public_key: 'aa'.repeat(32) },
    status: 'active',
  };
}

function makeDictCapabilityCard() {
  return {
    id: 'agent-a',
    capabilities: { 'carapace:read:email': true },
    owner: { public_key: 'aa'.repeat(32) },
    status: 'active',
  };
}

function makeToken(card = makeCard(), opts = {}) {
  return createDelegation({
    delegatorCard: card,
    delegateCardId: 'agent-b',
    capabilities: ['carapace:read:email'],
    ttlHours: 4,
    delegatorPrivateKey: 'deadbeef'.repeat(8),
    signFn: () => 'cafebabe'.repeat(16),
    ...opts,
  });
}

const verifySignatureFn = (_payload, signature) => signature === 'cafebabe'.repeat(16);

test('dict-form capability card matches object-form capability card', () => {
  const objectCard = makeCard();
  const dictCard = makeDictCapabilityCard();
  const token = makeToken(dictCard);
  const result = verifyDelegation(token, dictCard, { verifySignatureFn });

  assert.deepEqual(extractCapabilityIds(dictCard), extractCapabilityIds(objectCard));
  assert.equal(hasCapability(dictCard, 'carapace:read:email'), true);
  assert.equal(result.valid, true);
});

test('first use passes and second use is rejected', () => {
  const card = makeCard();
  const token = makeToken(card);
  const registry = new InMemoryNonceRegistry();

  const first = verifyDelegation(token, card, { verifySignatureFn, replayChecker: registry });
  const second = verifyDelegation(token, card, { verifySignatureFn, replayChecker: registry });

  assert.equal(first.valid, true);
  assert.equal(first.replayChecked, true);
  assert.equal(second.valid, false);
  assert.equal(second.reason, 'replay_detected');
});

test('expired token is rejected before replay check', () => {
  const card = makeCard();
  const token = makeToken(card, { expiresAt: new Date(Date.now() - 3600_000).toISOString() });
  const registry = new InMemoryNonceRegistry();

  const result = verifyDelegation(token, card, { verifySignatureFn, replayChecker: registry });

  assert.equal(result.valid, false);
  assert.equal(result.reason, 'delegation_expired');
  assert.equal(result.replayChecked, undefined);
});

test('missing nonce is rejected when replay checker is supplied', () => {
  const card = makeCard();
  const token = makeToken(card);
  token.nonce = '';

  const result = verifyDelegation(token, card, {
    verifySignatureFn,
    replayChecker: new InMemoryNonceRegistry(),
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, 'missing_nonce');
});

test('malformed nonce is rejected when replay checker is supplied', () => {
  const card = makeCard();
  const token = makeToken(card);
  token.nonce = 'not-a-valid-nonce';

  const result = verifyDelegation(token, card, {
    verifySignatureFn,
    replayChecker: new InMemoryNonceRegistry(),
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, 'malformed_nonce');
});

test('missing replay checker is explicit when required', () => {
  const card = makeCard();
  const token = makeToken(card);

  const result = verifyDelegation(token, card, {
    verifySignatureFn,
    requireReplayCheck: true,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, 'missing_replay_checker');
});

test('no replay checker is explicit fail-open behavior', () => {
  const card = makeCard();
  const token = makeToken(card);

  const first = verifyDelegation(token, card, { verifySignatureFn });
  const second = verifyDelegation(token, card, { verifySignatureFn });

  assert.equal(first.valid, true);
  assert.equal(second.valid, true);
  assert.equal(first.replayChecked, false);
  assert.equal(second.replayChecked, false);
});

test('chain replay checker rejects second chain use', () => {
  const card = makeCard();
  const token = makeToken(card);
  const registry = new InMemoryNonceRegistry();

  const first = verifyDelegationChain([token], card, { verifySignatureFn, replayChecker: registry });
  const second = verifyDelegationChain([token], card, { verifySignatureFn, replayChecker: registry });

  assert.equal(first.valid, true);
  assert.equal(first.replayChecked, true);
  assert.equal(second.valid, false);
  assert.equal(second.reason, 'replay_detected at link 0');
});
