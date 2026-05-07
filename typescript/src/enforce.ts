/**
 * Carapace v0.2 — Runtime Capability Enforcement (TypeScript)
 *
 * Middleware layer that gates API/tool calls based on declared capability scope.
 *
 * Usage:
 *   import { enforce, enforceAll, hasCapability, EnforcementPolicy } from './enforce';
 *
 *   enforce(card, 'carapace:write:database');
 *   enforceAll(card, ['carapace:read:email', 'carapace:write:email']);
 */

// ── Types ────────────────────────────────────────────────────────────────────

export interface Capability {
  id: string;
  name: string;
  description: string;
}

export type CapabilityInput = Capability | { id?: string } | string;
export type CapabilityCollection = CapabilityInput[] | Record<string, unknown>;

/** Minimum card shape needed for enforcement — AgentCard satisfies this. */
export interface CardLike {
  id?: string | null;
  capabilities?: CapabilityCollection;
  expires_at?: string | null;
}

// ── Errors ───────────────────────────────────────────────────────────────────

export class CapabilityDenied extends Error {
  readonly required: string;
  readonly agentId: string | null;
  readonly declared: string[];

  constructor(required: string, agentId?: string | null, declared?: string[]) {
    const msg = `Capability denied: '${required}' not declared${agentId ? ` by agent ${agentId}` : ''}`;
    super(msg);
    this.name = 'CapabilityDenied';
    this.required = required;
    this.agentId = agentId ?? null;
    this.declared = declared ?? [];
  }
}

export class CardExpired extends Error {
  readonly agentId: string | null;
  readonly expiresAt: string | null;

  constructor(agentId?: string | null, expiresAt?: string | null) {
    let msg = 'Card expired';
    if (agentId) msg += ` for agent ${agentId}`;
    if (expiresAt) msg += ` (expired at ${expiresAt})`;
    super(msg);
    this.name = 'CardExpired';
    this.agentId = agentId ?? null;
    this.expiresAt = expiresAt ?? null;
  }
}

// ── Internals ────────────────────────────────────────────────────────────────

export function extractCapabilityIds(card: CardLike): string[] {
  const caps = card.capabilities ?? [];

  if (!Array.isArray(caps) && typeof caps === 'object') {
    return Object.entries(caps)
      .filter(([capId, enabled]) => capId && enabled !== false && enabled != null)
      .map(([capId]) => capId);
  }

  if (Array.isArray(caps)) {
    return caps
      .map((cap) => {
        if (typeof cap === 'string') return cap;
        return cap.id ?? '';
      })
      .filter(Boolean);
  }

  return [];
}

function checkExpiry(card: CardLike): void {
  const expiresAt = card.expires_at;
  if (!expiresAt) return;

  const expDate = new Date(expiresAt);
  if (isNaN(expDate.getTime())) return; // Malformed — let verify() handle it

  if (Date.now() > expDate.getTime()) {
    throw new CardExpired(card.id, expiresAt);
  }
}

// ── Core Functions ───────────────────────────────────────────────────────────

/**
 * Check if a card declares a capability. Supports exact match and wildcard.
 *
 * hasCapability(card, 'carapace:read:email')     // exact
 * hasCapability(card, 'carapace:read:*')          // any read
 */
export function hasCapability(card: CardLike, required: string): boolean {
  const declared = extractCapabilityIds(card);

  // Exact match
  if (declared.includes(required)) return true;

  // Wildcard in required
  if (required.endsWith(':*')) {
    const prefix = required.slice(0, -1); // 'carapace:read:'
    return declared.some((d) => d.startsWith(prefix));
  }

  // Wildcard in declared
  for (const d of declared) {
    if (d.endsWith(':*')) {
      const prefix = d.slice(0, -1);
      if (required.startsWith(prefix)) return true;
    }
  }

  return false;
}

/**
 * Enforce a single capability. Throws CapabilityDenied if missing.
 * Checks card expiry first by default.
 */
export function enforce(
  card: CardLike,
  required: string,
  options?: { checkExpiry?: boolean },
): void {
  if (options?.checkExpiry !== false) {
    checkExpiry(card);
  }

  if (!hasCapability(card, required)) {
    throw new CapabilityDenied(required, card.id, extractCapabilityIds(card));
  }
}

/** Enforce ALL listed capabilities. Fails on first miss. */
export function enforceAll(
  card: CardLike,
  required: string[],
  options?: { checkExpiry?: boolean },
): void {
  if (options?.checkExpiry !== false) {
    checkExpiry(card);
  }
  for (const cap of required) {
    enforce(card, cap, { checkExpiry: false });
  }
}

/** Enforce AT LEAST ONE of the listed capabilities. */
export function enforceAny(
  card: CardLike,
  required: string[],
  options?: { checkExpiry?: boolean },
): void {
  if (options?.checkExpiry !== false) {
    checkExpiry(card);
  }
  for (const cap of required) {
    if (hasCapability(card, cap)) return;
  }
  throw new CapabilityDenied(
    `any of [${required.join(', ')}]`,
    card.id,
    extractCapabilityIds(card),
  );
}

// ── Enforcement Policy ───────────────────────────────────────────────────────

export interface PolicyRules {
  [action: string]: string[];
}

export class EnforcementPolicy {
  readonly name: string;
  readonly rules: PolicyRules;

  constructor(name: string, rules: PolicyRules) {
    this.name = name;
    this.rules = rules;
  }

  enforce(card: CardLike, action: string): void {
    const required = this.rules[action];
    if (!required) {
      throw new Error(
        `Unknown action '${action}' in policy '${this.name}'. ` +
          `Known actions: ${Object.keys(this.rules).join(', ')}`,
      );
    }
    enforceAll(card, required);
  }

  hasAccess(card: CardLike, action: string): boolean {
    const required = this.rules[action];
    if (!required) return false;
    return required.every((r) => hasCapability(card, r));
  }

  auditCard(card: CardLike): Record<string, boolean> {
    const result: Record<string, boolean> = {};
    for (const action of Object.keys(this.rules)) {
      result[action] = this.hasAccess(card, action);
    }
    return result;
  }
}
