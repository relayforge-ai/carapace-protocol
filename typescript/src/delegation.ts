/**
 * Carapace v0.3 — Delegation Chains (TypeScript mirror of delegation.py)
 */

import { hasCapability, extractCapabilityIds, CardLike } from "./enforce";
import { parseExpiresAt, isExpired } from "./expiry";

// ── Constants ─────────────────────────────────────────────────────────────────

export const MAX_CHAIN_DEPTH = 5;
export const DEFAULT_MAX_TTL_HOURS = 24;
export const DEFAULT_REDELEGATION_DEPTH = 2;

// ── Errors ────────────────────────────────────────────────────────────────────

export class DelegationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DelegationError';
  }
}

export class DelegationSigningError extends DelegationError {
  constructor(message: string) {
    super(message);
    this.name = 'DelegationSigningError';
  }
}

export class CapabilityEscalation extends DelegationError {
  readonly requested: string[];
  readonly available: string[];
  constructor(requested: string[], available: string[]) {
    const escalated = requested.filter((r) => !available.includes(r));
    super(`Capability escalation: [${escalated.join(', ')}] not in delegator's capabilities`);
    this.name = 'CapabilityEscalation';
    this.requested = requested;
    this.available = available;
  }
}

export class DelegationExpired extends DelegationError {
  constructor(message: string) {
    super(message);
    this.name = 'DelegationExpired';
  }
}

export class RedelegationDepthExceeded extends DelegationError {
  constructor(message: string) {
    super(message);
    this.name = 'RedelegationDepthExceeded';
  }
}

export class DelegatorCardInvalid extends DelegationError {
  constructor(message: string) {
    super(message);
    this.name = 'DelegatorCardInvalid';
  }
}

export class TTLExceedsDelegator extends DelegationError {
  constructor(message: string) {
    super(message);
    this.name = 'TTLExceedsDelegator';
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface DelegationToken {
  id: string;
  delegator_card_id: string;
  delegator_public_key: string;
  delegate_card_id: string;
  delegated_capabilities: string[];
  expires_at: string;
  created_at: string;
  parent_delegation_id: string | null;
  max_redelegation_depth: number;
  task_context: string | null;
  nonce: string;
  signature: string;
}

export interface DelegationVerifyResult {
  valid: boolean;
  reason?: string | null;
  tokenId?: string | null;
  delegatorCardId?: string | null;
  delegateCardId?: string | null;
  capabilities?: string[];
  chainDepth?: number;
  expiresAt?: string | null;
}

export interface CreateDelegationOptions {
  delegatorCard: CardLike & { id?: string; owner?: { public_key: string }; expires_at?: string | null; status?: string };
  delegateCardId: string;
  capabilities: string[];
  delegatorPrivateKey?: string;
  ttlHours?: number;
  ttlMinutes?: number;
  expiresAt?: string;
  parentDelegation?: DelegationToken;
  maxRedelegationDepth?: number;
  taskContext?: string;
  signFn?: (payload: Uint8Array, privateKeyHex: string) => string;
  /**
   * When true, return an unsigned token if signing is unavailable.
   * **For testing/development only.** Production callers must provide signing
   * credentials; omitting them throws DelegationSigningError by default.
   */
  allowUnsigned?: boolean;
}

// ── Internals ────────────────────────────────────────────────────────────────

function extractCapIds(card: any): string[] {
  const caps: any[] = card.capabilities ?? [];
  return caps.map((c: any) => c.id).filter(Boolean);
}

function generateNonce(): string {
  const arr = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(arr);
  } else {
    for (let i = 0; i < 16; i++) arr[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

function generateUUID(): string {
  // Simple v4 UUID
  const hex = generateNonce() + generateNonce();
  return [
    hex.slice(0, 8), hex.slice(8, 12),
    '4' + hex.slice(13, 16),
    ((parseInt(hex[16], 16) & 0x3) | 0x8).toString(16) + hex.slice(17, 20),
    hex.slice(20, 32),
  ].join('-');
}

function isCardExpired(card: any): boolean {
  const exp = card.expires_at;
  if (!exp) return false;
  return new Date(exp).getTime() < Date.now();
}

// ── Capability Subset Validation ─────────────────────────────────────────────

export function validateCapabilitySubset(requested: string[], available: string[]): void {
  for (const req of requested) {
    let covered = false;

    if (available.includes(req)) {
      covered = true;
    } else {
      // Wildcard in available
      for (const avail of available) {
        if (avail.endsWith(':*')) {
          const prefix = avail.slice(0, -1);
          if (req.startsWith(prefix)) { covered = true; break; }
        }
      }
      // Wildcard narrowing
      if (!covered && req.endsWith(':*')) {
        const reqPrefix = req.slice(0, -1);
        for (const avail of available) {
          if (avail.endsWith(':*')) {
            const availPrefix = avail.slice(0, -1);
            if (reqPrefix.startsWith(availPrefix)) { covered = true; break; }
          }
        }
      }
    }

    if (!covered) {
      throw new CapabilityEscalation(requested, available);
    }
  }
}

// ── Signable Payload ─────────────────────────────────────────────────────────

export function signablePayload(token: DelegationToken): string {
  const obj: Record<string, any> = {
    created_at: token.created_at,
    delegate_card_id: token.delegate_card_id,
    delegated_capabilities: [...token.delegated_capabilities].sort(),
    delegator_card_id: token.delegator_card_id,
    delegator_public_key: token.delegator_public_key,
    expires_at: token.expires_at,
    id: token.id,
    max_redelegation_depth: token.max_redelegation_depth,
    nonce: token.nonce,
    parent_delegation_id: token.parent_delegation_id,
    task_context: token.task_context,
  };
  // JCS: sorted keys, no whitespace
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// ── Create Delegation ────────────────────────────────────────────────────────

export function createDelegation(opts: CreateDelegationOptions): DelegationToken {
  const {
    delegatorCard, delegateCardId, capabilities,
    delegatorPrivateKey, ttlHours, ttlMinutes, expiresAt,
    parentDelegation, taskContext, signFn,
    allowUnsigned = false,
  } = opts;
  let { maxRedelegationDepth } = opts;

  const now = new Date();
  const delegatorId = (delegatorCard as any).id ?? '';
  const delegatorPubKey = (delegatorCard as any).owner?.public_key ?? '';
  const delegatorCaps = extractCapIds(delegatorCard);
  const delegatorExpiry = (delegatorCard as any).expires_at ?? null;

  // Check delegator validity
  if (isCardExpired(delegatorCard)) {
    throw new DelegatorCardInvalid("Delegator's card has expired");
  }
  const status = (delegatorCard as any).status ?? 'active';
  if (status === 'revoked' || status === 'superseded') {
    throw new DelegatorCardInvalid(`Delegator's card status is '${status}'`);
  }

  // Re-delegation constraints
  let effectiveCaps = delegatorCaps;
  let effectiveExpiry = delegatorExpiry;

  if (parentDelegation) {
    if (parentDelegation.max_redelegation_depth <= 0) {
      throw new RedelegationDepthExceeded(
        `Parent delegation ${parentDelegation.id} has max_redelegation_depth=0`
      );
    }
    effectiveCaps = parentDelegation.delegated_capabilities;
    const parentDepth = parentDelegation.max_redelegation_depth;
    if (maxRedelegationDepth == null) {
      maxRedelegationDepth = parentDepth - 1;
    } else if (maxRedelegationDepth >= parentDepth) {
      maxRedelegationDepth = parentDepth - 1;
    }
    effectiveExpiry = parentDelegation.expires_at;
  } else {
    if (maxRedelegationDepth == null) {
      maxRedelegationDepth = DEFAULT_REDELEGATION_DEPTH;
    }
  }

  maxRedelegationDepth = Math.min(maxRedelegationDepth, MAX_CHAIN_DEPTH);

  // Validate subset
  validateCapabilitySubset(capabilities, effectiveCaps);

  // Resolve expiry
  let tokenExpiry: string;
  if (expiresAt) {
    tokenExpiry = expiresAt;
  } else if (ttlHours != null || ttlMinutes != null) {
    const ms = ((ttlHours ?? 0) * 3600 + (ttlMinutes ?? 0) * 60) * 1000;
    tokenExpiry = new Date(now.getTime() + ms).toISOString();
  } else if (effectiveExpiry) {
    tokenExpiry = effectiveExpiry;
  } else {
    tokenExpiry = new Date(now.getTime() + DEFAULT_MAX_TTL_HOURS * 3600000).toISOString();
  }

  // TTL check
  if (effectiveExpiry) {
    if (new Date(tokenExpiry).getTime() > new Date(effectiveExpiry).getTime()) {
      throw new TTLExceedsDelegator(
        `Delegation expires at ${tokenExpiry} but delegator expires at ${effectiveExpiry}`
      );
    }
  }

  const token: DelegationToken = {
    id: generateUUID(),
    delegator_card_id: delegatorId,
    delegator_public_key: delegatorPubKey,
    delegate_card_id: delegateCardId,
    delegated_capabilities: [...capabilities].sort(),
    expires_at: tokenExpiry,
    created_at: now.toISOString(),
    parent_delegation_id: parentDelegation?.id ?? null,
    max_redelegation_depth: maxRedelegationDepth,
    task_context: taskContext ?? null,
    nonce: generateNonce(),
    signature: '',
  };

  // Sign
  let signed = false;
  if (signFn && delegatorPrivateKey) {
    try {
      const payload = new TextEncoder().encode(signablePayload(token));
      token.signature = signFn(payload, delegatorPrivateKey);
      signed = true;
    } catch (e) {
      if (!allowUnsigned) {
        throw new DelegationSigningError(
          `Signing failed: ${e}. Pass allowUnsigned: true (test/dev only) to suppress this error.`
        );
      }
    }
  }

  if (!signed && !allowUnsigned) {
    throw new DelegationSigningError(
      'No signing credentials provided. Supply delegatorPrivateKey and signFn, or pass ' +
      'allowUnsigned: true (test/dev only) to create an unsigned delegation token.'
    );
  }

  return token;
}

// ── Verify Single Token ──────────────────────────────────────────────────────

export function verifyDelegation(
  token: DelegationToken,
  delegatorCard: any,
  options?: {
    verifySignatureFn?: (payload: Uint8Array, sig: string, pubKey: string) => boolean;
    now?: Date;
    /**
     * When true (default), tokens without a signature are rejected and
     * verifySignatureFn must be provided. Set to false only in test/dev
     * environments where signatures are intentionally absent.
     */
    strict?: boolean;
  },
): DelegationVerifyResult {
  const now = options?.now ?? new Date();
  const strict = options?.strict ?? true;

  // Token expiry
  if (new Date(token.expires_at).getTime() < now.getTime()) {
    return { valid: false, reason: 'delegation_expired', tokenId: token.id, expiresAt: token.expires_at };
  }

  // Card validity
  if (isCardExpired(delegatorCard)) {
    return { valid: false, reason: 'delegator_card_expired', tokenId: token.id, delegatorCardId: token.delegator_card_id };
  }
  const status = delegatorCard.status ?? 'active';
  if (status === 'revoked' || status === 'superseded') {
    return { valid: false, reason: `delegator_card_${status}`, tokenId: token.id, delegatorCardId: token.delegator_card_id };
  }

  // Card ID match
  if (delegatorCard.id && token.delegator_card_id !== delegatorCard.id) {
    return { valid: false, reason: 'delegator_card_id_mismatch', tokenId: token.id, delegatorCardId: token.delegator_card_id };
  }

  // Capability subset
  const cardCaps = extractCapIds(delegatorCard);
  try {
    validateCapabilitySubset(token.delegated_capabilities, cardCaps);
  } catch {
    return { valid: false, reason: 'capability_escalation', tokenId: token.id };
  }

  // Signature
  if (strict) {
    if (!token.signature) {
      return { valid: false, reason: 'unsigned_token', tokenId: token.id };
    }
    if (!options?.verifySignatureFn) {
      return { valid: false, reason: 'missing_verify_signature_fn', tokenId: token.id };
    }
  }

  if (options?.verifySignatureFn && token.signature) {
    const payload = new TextEncoder().encode(signablePayload(token));
    try {
      if (!options.verifySignatureFn(payload, token.signature, token.delegator_public_key)) {
        return { valid: false, reason: 'signature_invalid', tokenId: token.id };
      }
    } catch (e) {
      return { valid: false, reason: `signature_error: ${e}`, tokenId: token.id };
    }
  }

  return {
    valid: true,
    tokenId: token.id,
    delegatorCardId: token.delegator_card_id,
    delegateCardId: token.delegate_card_id,
    capabilities: token.delegated_capabilities,
    chainDepth: token.parent_delegation_id ? 1 : 0,
    expiresAt: token.expires_at,
  };
}

// ── Verify Chain ─────────────────────────────────────────────────────────────

export function verifyDelegationChain(
  tokens: DelegationToken[],
  rootCard: any,
  options?: {
    verifySignatureFn?: (payload: Uint8Array, sig: string, pubKey: string) => boolean;
    now?: Date;
    /**
     * When true (default), tokens without a signature are rejected and
     * verifySignatureFn must be provided. Set to false only in test/dev
     * environments where signatures are intentionally absent.
     */
    strict?: boolean;
  },
): DelegationVerifyResult {
  if (tokens.length === 0) {
    return { valid: false, reason: 'empty_chain' };
  }

  const now = options?.now ?? new Date();
  const strict = options?.strict ?? true;

  // Verify root
  const rootResult = verifyDelegation(tokens[0], rootCard, { ...options, now });
  if (!rootResult.valid) {
    return { valid: false, reason: `root_link_failed: ${rootResult.reason}`, tokenId: tokens[0].id, chainDepth: 0 };
  }

  if (tokens[0].parent_delegation_id !== null) {
    return { valid: false, reason: 'first_token_is_not_root (has parent_delegation_id)', tokenId: tokens[0].id };
  }

  let prevToken = tokens[0];
  let prevCaps = prevToken.delegated_capabilities;
  let prevExpiry = new Date(prevToken.expires_at).getTime();

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];

    // Parent reference
    if (token.parent_delegation_id !== prevToken.id) {
      return {
        valid: false,
        reason: `parent_delegation_id mismatch at link ${i}: expected ${prevToken.id}, got ${token.parent_delegation_id}`,
        tokenId: token.id, chainDepth: i,
      };
    }

    // Chain continuity
    if (prevToken.delegate_card_id !== token.delegator_card_id) {
      return {
        valid: false,
        reason: `chain discontinuity at link ${i}: prev delegate ${prevToken.delegate_card_id} != current delegator ${token.delegator_card_id}`,
        tokenId: token.id, chainDepth: i,
      };
    }

    // Capability narrowing
    try {
      validateCapabilitySubset(token.delegated_capabilities, prevCaps);
    } catch {
      return { valid: false, reason: `capability_escalation at link ${i}`, tokenId: token.id, chainDepth: i };
    }

    // TTL narrowing
    const tokenExp = new Date(token.expires_at).getTime();
    if (tokenExp > prevExpiry) {
      return {
        valid: false,
        reason: `ttl_escalation at link ${i}: ${token.expires_at} exceeds parent ${prevToken.expires_at}`,
        tokenId: token.id, chainDepth: i,
      };
    }

    // Depth
    if (prevToken.max_redelegation_depth <= 0) {
      return { valid: false, reason: `redelegation_depth_exceeded at link ${i}`, tokenId: token.id, chainDepth: i };
    }

    // Expiry
    if (tokenExp < now.getTime()) {
      return { valid: false, reason: `delegation_expired at link ${i}`, tokenId: token.id, chainDepth: i };
    }

    // Signature (strict mode)
    if (strict) {
      if (!token.signature) {
        return { valid: false, reason: `unsigned_token at link ${i}`, tokenId: token.id, chainDepth: i };
      }
      if (!options?.verifySignatureFn) {
        return { valid: false, reason: `missing_verify_signature_fn at link ${i}`, tokenId: token.id, chainDepth: i };
      }
    }

    if (options?.verifySignatureFn && token.signature) {
      const payload = new TextEncoder().encode(signablePayload(token));
      try {
        if (!options.verifySignatureFn(payload, token.signature, token.delegator_public_key)) {
          return { valid: false, reason: `signature_invalid at link ${i}`, tokenId: token.id, chainDepth: i };
        }
      } catch (e) {
        return { valid: false, reason: `signature_error at link ${i}: ${e}`, tokenId: token.id, chainDepth: i };
      }
    }

    prevToken = token;
    prevCaps = token.delegated_capabilities;
    prevExpiry = tokenExp;
  }

  const final = tokens[tokens.length - 1];
  return {
    valid: true,
    tokenId: final.id,
    delegatorCardId: tokens[0].delegator_card_id,
    delegateCardId: final.delegate_card_id,
    capabilities: final.delegated_capabilities,
    chainDepth: tokens.length,
    expiresAt: final.expires_at,
  };
}

// ── Enforce Through Delegation ───────────────────────────────────────────────

export function enforceDelegated(token: DelegationToken, required: string, now?: Date): void {
  const current = now ?? new Date();
  if (new Date(token.expires_at).getTime() < current.getTime()) {
    throw new DelegationExpired(`Delegation ${token.id} expired at ${token.expires_at}`);
  }

  const caps = token.delegated_capabilities;
  let covered = false;

  if (caps.includes(required)) covered = true;
  if (!covered && required.endsWith(':*')) {
    const prefix = required.slice(0, -1);
    covered = caps.some((c) => c.startsWith(prefix));
  }
  if (!covered) {
    for (const c of caps) {
      if (c.endsWith(':*') && required.startsWith(c.slice(0, -1))) {
        covered = true;
        break;
      }
    }
  }

  if (!covered) {
    throw new CapabilityEscalation([required], caps);
  }
}

// ── Re-delegation Helper ─────────────────────────────────────────────────────

export function redelegate(opts: {
  parentToken: DelegationToken;
  redelegatorCard: any;
  delegateCardId: string;
  capabilities: string[];
  redelegatorPrivateKey?: string;
  ttlHours?: number;
  ttlMinutes?: number;
  taskContext?: string;
  signFn?: (payload: Uint8Array, privateKeyHex: string) => string;
  /** Passed through to createDelegation. For test/dev only. */
  allowUnsigned?: boolean;
}): DelegationToken {
  return createDelegation({
    delegatorCard: opts.redelegatorCard,
    delegateCardId: opts.delegateCardId,
    capabilities: opts.capabilities,
    delegatorPrivateKey: opts.redelegatorPrivateKey,
    ttlHours: opts.ttlHours,
    ttlMinutes: opts.ttlMinutes,
    parentDelegation: opts.parentToken,
    taskContext: opts.taskContext,
    signFn: opts.signFn,
    allowUnsigned: opts.allowUnsigned,
  });
}
