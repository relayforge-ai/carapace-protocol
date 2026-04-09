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
    this.name = "DelegationError";
  }
}

export class CapabilityEscalation extends DelegationError {
  constructor(
    public readonly requested: string[],
    public readonly available: string[],
  ) {
    const escalated = requested.filter((r) => !available.includes(r));
    super(`Capability escalation: ${JSON.stringify(escalated)} not in delegator's capabilities`);
    this.name = "CapabilityEscalation";
  }
}

export class DelegationExpired extends DelegationError {
  constructor(message: string) { super(message); this.name = "DelegationExpired"; }
}

export class DelegationChainBroken extends DelegationError {
  constructor(public readonly linkIndex: number, reason: string) {
    super(`Chain broken at link ${linkIndex}: ${reason}`);
    this.name = "DelegationChainBroken";
  }
}

export class RedelegationDepthExceeded extends DelegationError {
  constructor(message: string) { super(message); this.name = "RedelegationDepthExceeded"; }
}

export class DelegatorCardInvalid extends DelegationError {
  constructor(message: string) { super(message); this.name = "DelegatorCardInvalid"; }
}

export class TTLExceedsDelegator extends DelegationError {
  constructor(message: string) { super(message); this.name = "TTLExceedsDelegator"; }
}

export class SignatureInvalid extends DelegationError {
  constructor(message: string) { super(message); this.name = "SignatureInvalid"; }
}

// ── Delegation Token ──────────────────────────────────────────────────────────

export interface DelegationTokenData {
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

export class DelegationToken implements DelegationTokenData {
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

  constructor(data: DelegationTokenData) {
    Object.assign(this, data);
    this.id = data.id;
    this.delegator_card_id = data.delegator_card_id;
    this.delegator_public_key = data.delegator_public_key;
    this.delegate_card_id = data.delegate_card_id;
    this.delegated_capabilities = [...data.delegated_capabilities].sort();
    this.expires_at = data.expires_at;
    this.created_at = data.created_at;
    this.parent_delegation_id = data.parent_delegation_id;
    this.max_redelegation_depth = data.max_redelegation_depth;
    this.task_context = data.task_context;
    this.nonce = data.nonce;
    this.signature = data.signature;
  }

  get isRoot(): boolean { return this.parent_delegation_id === null; }
  get canRedelegate(): boolean { return this.max_redelegation_depth > 0; }

  toDict(): Omit<DelegationTokenData, "signature"> {
    return {
      id: this.id,
      delegator_card_id: this.delegator_card_id,
      delegator_public_key: this.delegator_public_key,
      delegate_card_id: this.delegate_card_id,
      delegated_capabilities: [...this.delegated_capabilities].sort(),
      expires_at: this.expires_at,
      created_at: this.created_at,
      parent_delegation_id: this.parent_delegation_id,
      max_redelegation_depth: this.max_redelegation_depth,
      task_context: this.task_context,
      nonce: this.nonce,
    };
  }

  signablePayload(): string {
    return JSON.stringify(this.toDict(), Object.keys(this.toDict()).sort());
  }

  static fromDict(data: Record<string, unknown>): DelegationToken {
    return new DelegationToken({
      id: (data.id as string) ?? "",
      delegator_card_id: data.delegator_card_id as string,
      delegator_public_key: data.delegator_public_key as string,
      delegate_card_id: data.delegate_card_id as string,
      delegated_capabilities: (data.delegated_capabilities as string[]) ?? [],
      expires_at: data.expires_at as string,
      created_at: data.created_at as string,
      parent_delegation_id: (data.parent_delegation_id as string | null) ?? null,
      max_redelegation_depth: (data.max_redelegation_depth as number) ?? DEFAULT_REDELEGATION_DEPTH,
      task_context: (data.task_context as string | null) ?? null,
      nonce: (data.nonce as string) ?? "",
      signature: (data.signature as string) ?? "",
    });
  }
}

// ── Verify Result ─────────────────────────────────────────────────────────────

export interface DelegationVerifyResult {
  valid: boolean;
  reason: string | null;
  token_id: string | null;
  delegator_card_id: string | null;
  delegate_card_id: string | null;
  capabilities: string[];
  chain_depth: number;
  expires_at: string | null;
}

// ── Capability Subset Validation ──────────────────────────────────────────────

export function validateCapabilitySubset(
  requested: string[],
  available: string[],
): void {
  for (const req of requested) {
    let covered = false;

    if (available.includes(req)) {
      covered = true;
    } else {
      for (const avail of available) {
        if (avail.endsWith(":*")) {
          const prefix = avail.slice(0, -1);
          if (req.startsWith(prefix)) { covered = true; break; }
        }
      }
      if (!covered && req.endsWith(":*")) {
        const reqPrefix = req.slice(0, -1);
        for (const avail of available) {
          if (avail.endsWith(":*")) {
            const availPrefix = avail.slice(0, -1);
            if (reqPrefix.startsWith(availPrefix)) { covered = true; break; }
          }
        }
      }
    }

    if (!covered) throw new CapabilityEscalation(requested, available);
  }
}

// ── Token Creation ────────────────────────────────────────────────────────────

export interface CreateDelegationOptions {
  delegatorCard: CardLike & { id?: string; status?: string; expires_at?: string | null; owner?: { public_key: string } };
  delegateCardId: string;
  capabilities: string[];
  ttlHours?: number;
  ttlMinutes?: number;
  expiresAt?: string;
  parentDelegation?: DelegationToken;
  maxRedelegationDepth?: number;
  taskContext?: string;
}

export function createDelegation(opts: CreateDelegationOptions): DelegationToken {
  const {
    delegatorCard,
    delegateCardId,
    capabilities,
    ttlHours,
    ttlMinutes,
    expiresAt,
    parentDelegation,
    taskContext,
  } = opts;

  const now = new Date();

  const delegatorId = delegatorCard.id ?? "";
  const delegatorPubkey = delegatorCard.owner?.public_key ?? "";
  const delegatorCaps = extractCapabilityIds(delegatorCard as CardLike);
  const delegatorExpiry = delegatorCard.expires_at ?? null;
  const status = (delegatorCard as { status?: string }).status ?? "active";

  if (isExpired(delegatorCard as { expires_at?: string | null })) {
    throw new DelegatorCardInvalid("Delegator's card has expired");
  }
  if (status === "revoked" || status === "superseded") {
    throw new DelegatorCardInvalid(`Delegator's card status is '${status}'`);
  }

  let effectiveCaps = delegatorCaps;
  let effectiveMaxDepth = opts.maxRedelegationDepth ?? null;

  if (parentDelegation) {
    if (!parentDelegation.canRedelegate) {
      throw new RedelegationDepthExceeded(
        `Parent delegation has max_redelegation_depth=0 — cannot re-delegate`,
      );
    }
    effectiveCaps = parentDelegation.delegated_capabilities;
    const parentDepth = parentDelegation.max_redelegation_depth;
    if (effectiveMaxDepth === null) {
      effectiveMaxDepth = parentDepth - 1;
    } else if (effectiveMaxDepth >= parentDepth) {
      effectiveMaxDepth = parentDepth - 1;
    }
  } else {
    if (effectiveMaxDepth === null) effectiveMaxDepth = DEFAULT_REDELEGATION_DEPTH;
  }

  effectiveMaxDepth = Math.min(effectiveMaxDepth!, MAX_CHAIN_DEPTH);

  validateCapabilitySubset(capabilities, effectiveCaps);

  let tokenExpiry: string;
  if (expiresAt) {
    tokenExpiry = expiresAt;
  } else if (ttlHours !== undefined || ttlMinutes !== undefined) {
    const ms = ((ttlHours ?? 0) * 3600 + (ttlMinutes ?? 0) * 60) * 1000;
    tokenExpiry = new Date(now.getTime() + ms).toISOString();
  } else {
    if (delegatorExpiry) {
      tokenExpiry = delegatorExpiry;
    } else {
      tokenExpiry = new Date(now.getTime() + DEFAULT_MAX_TTL_HOURS * 3600 * 1000).toISOString();
    }
  }

  const tokenExpDt = parseExpiresAt(tokenExpiry);
  if (delegatorExpiry) {
    const delegatorExpDt = parseExpiresAt(delegatorExpiry);
    if (tokenExpDt && delegatorExpDt && tokenExpDt > delegatorExpDt) {
      throw new TTLExceedsDelegator(
        `Delegation expires at ${tokenExpiry} but delegator's card expires at ${delegatorExpiry}`,
      );
    }
  }

  const nonce = Array.from(
    { length: 32 },
    () => Math.floor(Math.random() * 16).toString(16),
  ).join("");

  return new DelegationToken({
    id: crypto.randomUUID?.() ?? Math.random().toString(36).slice(2),
    delegator_card_id: delegatorId,
    delegator_public_key: delegatorPubkey,
    delegate_card_id: delegateCardId,
    delegated_capabilities: [...capabilities].sort(),
    expires_at: tokenExpiry,
    created_at: now.toISOString(),
    parent_delegation_id: parentDelegation?.id ?? null,
    max_redelegation_depth: effectiveMaxDepth,
    task_context: taskContext ?? null,
    nonce,
    signature: "",
  });
}

// ── Chain Verification ────────────────────────────────────────────────────────

export function verifyDelegationChain(
  tokens: DelegationToken[],
  rootCard: CardLike & { id?: string; status?: string; expires_at?: string | null },
  opts: { now?: Date } = {},
): DelegationVerifyResult {
  if (!tokens.length) {
    return { valid: false, reason: "empty_chain", token_id: null, delegator_card_id: null, delegate_card_id: null, capabilities: [], chain_depth: 0, expires_at: null };
  }

  const current = opts.now ?? new Date();

  // Verify root
  const root = tokens[0];
  if (root.parent_delegation_id !== null) {
    return { valid: false, reason: "first_token_is_not_root (has parent_delegation_id)", token_id: root.id, delegator_card_id: null, delegate_card_id: null, capabilities: [], chain_depth: 0, expires_at: null };
  }

  if (isExpired(rootCard as { expires_at?: string | null }, { now: current })) {
    return { valid: false, reason: "root_link_failed: delegator_card_expired", token_id: root.id, delegator_card_id: root.delegator_card_id, delegate_card_id: null, capabilities: [], chain_depth: 0, expires_at: null };
  }

  const rootStatus = (rootCard as { status?: string }).status ?? "active";
  if (rootStatus === "revoked" || rootStatus === "superseded") {
    return { valid: false, reason: `root_link_failed: delegator_card_${rootStatus}`, token_id: root.id, delegator_card_id: root.delegator_card_id, delegate_card_id: null, capabilities: [], chain_depth: 0, expires_at: null };
  }

  const rootCardId = rootCard.id;
  if (rootCardId && root.delegator_card_id !== rootCardId) {
    return { valid: false, reason: "root_link_failed: delegator_card_id_mismatch", token_id: root.id, delegator_card_id: root.delegator_card_id, delegate_card_id: null, capabilities: [], chain_depth: 0, expires_at: null };
  }

  const rootCardCaps = extractCapabilityIds(rootCard as CardLike);
  try {
    validateCapabilitySubset(root.delegated_capabilities, rootCardCaps);
  } catch {
    return { valid: false, reason: "root_link_failed: capability_escalation", token_id: root.id, delegator_card_id: root.delegator_card_id, delegate_card_id: null, capabilities: [], chain_depth: 0, expires_at: null };
  }

  const rootExp = parseExpiresAt(root.expires_at);
  if (rootExp && current > rootExp) {
    return { valid: false, reason: "root_link_failed: delegation_expired", token_id: root.id, delegator_card_id: root.delegator_card_id, delegate_card_id: null, capabilities: [], chain_depth: 0, expires_at: null };
  }

  let prevToken = root;
  let prevCaps = root.delegated_capabilities;
  let prevExpiry = parseExpiresAt(root.expires_at);

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];

    if (token.parent_delegation_id !== prevToken.id) {
      return { valid: false, reason: `parent_delegation_id mismatch at link ${i}: expected ${prevToken.id}, got ${token.parent_delegation_id}`, token_id: token.id, delegator_card_id: null, delegate_card_id: null, capabilities: [], chain_depth: i, expires_at: null };
    }

    if (prevToken.delegate_card_id !== token.delegator_card_id) {
      return { valid: false, reason: `chain discontinuity at link ${i}: prev delegate ${prevToken.delegate_card_id} != current delegator ${token.delegator_card_id}`, token_id: token.id, delegator_card_id: null, delegate_card_id: null, capabilities: [], chain_depth: i, expires_at: null };
    }

    try {
      validateCapabilitySubset(token.delegated_capabilities, prevCaps);
    } catch {
      return { valid: false, reason: `capability_escalation at link ${i}`, token_id: token.id, delegator_card_id: null, delegate_card_id: null, capabilities: [], chain_depth: i, expires_at: null };
    }

    const tokenExp = parseExpiresAt(token.expires_at);
    if (tokenExp && prevExpiry && tokenExp > prevExpiry) {
      return { valid: false, reason: `ttl_escalation at link ${i}: ${token.expires_at} exceeds parent ${prevToken.expires_at}`, token_id: token.id, delegator_card_id: null, delegate_card_id: null, capabilities: [], chain_depth: i, expires_at: null };
    }

    if (prevToken.max_redelegation_depth <= 0) {
      return { valid: false, reason: `redelegation_depth_exceeded at link ${i}`, token_id: token.id, delegator_card_id: null, delegate_card_id: null, capabilities: [], chain_depth: i, expires_at: null };
    }

    const tokenExpCheck = parseExpiresAt(token.expires_at);
    if (tokenExpCheck && current > tokenExpCheck) {
      return { valid: false, reason: `delegation_expired at link ${i}`, token_id: token.id, delegator_card_id: null, delegate_card_id: null, capabilities: [], chain_depth: i, expires_at: null };
    }

    prevToken = token;
    prevCaps = token.delegated_capabilities;
    prevExpiry = parseExpiresAt(token.expires_at);
  }

  const final = tokens[tokens.length - 1];
  return {
    valid: true,
    reason: null,
    token_id: final.id,
    delegator_card_id: tokens[0].delegator_card_id,
    delegate_card_id: final.delegate_card_id,
    capabilities: final.delegated_capabilities,
    chain_depth: tokens.length,
    expires_at: final.expires_at,
  };
}

// ── Re-delegation helper ──────────────────────────────────────────────────────

export function redelegate(
  parentToken: DelegationToken,
  redelegatorCard: CardLike & { id?: string; status?: string; expires_at?: string | null; owner?: { public_key: string } },
  delegateCardId: string,
  capabilities: string[],
  opts: { ttlHours?: number; ttlMinutes?: number; taskContext?: string } = {},
): DelegationToken {
  return createDelegation({
    delegatorCard: redelegatorCard,
    delegateCardId,
    capabilities,
    ttlHours: opts.ttlHours,
    ttlMinutes: opts.ttlMinutes,
    parentDelegation: parentToken,
    taskContext: opts.taskContext,
  });
}
