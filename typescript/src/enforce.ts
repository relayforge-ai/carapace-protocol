/**
 * Carapace v0.2 — Runtime Capability Enforcement (TypeScript mirror of enforce.py)
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export interface CardLike {
  id?: string | null;
  capabilities: Array<{ id: string } | string>;
  expires_at?: string | null;
}

// ── Errors ────────────────────────────────────────────────────────────────────

export class CapabilityDenied extends Error {
  constructor(
    public readonly required: string,
    public readonly agentId?: string | null,
    public readonly declared: string[] = [],
  ) {
    let msg = `Capability denied: '${required}' not declared`;
    if (agentId) msg += ` by agent ${agentId}`;
    super(msg);
    this.name = "CapabilityDenied";
  }
}

export class CardExpired extends Error {
  constructor(
    public readonly agentId?: string | null,
    public readonly expiresAt?: string | null,
  ) {
    let msg = "Card expired";
    if (agentId) msg += ` for agent ${agentId}`;
    if (expiresAt) msg += ` (expired at ${expiresAt})`;
    super(msg);
    this.name = "CardExpired";
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function extractCapabilityIds(card: CardLike): string[] {
  return card.capabilities.map((c) =>
    typeof c === "string" ? c : c.id,
  );
}

export function checkExpiry(card: CardLike): void {
  const expiresAt = card.expires_at;
  if (!expiresAt) return;

  const expDt = new Date(expiresAt);
  if (isNaN(expDt.getTime())) return; // malformed — don't block

  if (Date.now() > expDt.getTime()) {
    throw new CardExpired(card.id ?? null, expiresAt);
  }
}

// ── Core enforcement ──────────────────────────────────────────────────────────

export function hasCapability(card: CardLike, required: string): boolean {
  const declared = extractCapabilityIds(card);

  if (declared.includes(required)) return true;

  // Wildcard in required
  if (required.endsWith(":*")) {
    const prefix = required.slice(0, -1);
    if (declared.some((d) => d.startsWith(prefix))) return true;
  }

  // Wildcard in declared
  for (const d of declared) {
    if (d.endsWith(":*")) {
      const prefix = d.slice(0, -1);
      if (required.startsWith(prefix)) return true;
    }
  }

  return false;
}

export function enforce(
  card: CardLike,
  required: string,
  { checkExpiryFlag = true }: { checkExpiryFlag?: boolean } = {},
): void {
  if (checkExpiryFlag) checkExpiry(card);
  if (!hasCapability(card, required)) {
    throw new CapabilityDenied(required, card.id, extractCapabilityIds(card));
  }
}

export function enforceAll(
  card: CardLike,
  required: string[],
  { checkExpiryFlag = true }: { checkExpiryFlag?: boolean } = {},
): void {
  if (checkExpiryFlag) checkExpiry(card);
  for (const cap of required) {
    enforce(card, cap, { checkExpiryFlag: false });
  }
}

export function enforceAny(
  card: CardLike,
  required: string[],
  { checkExpiryFlag = true }: { checkExpiryFlag?: boolean } = {},
): void {
  if (checkExpiryFlag) checkExpiry(card);
  for (const cap of required) {
    if (hasCapability(card, cap)) return;
  }
  throw new CapabilityDenied(
    `any of [${required.join(", ")}]`,
    card.id,
    extractCapabilityIds(card),
  );
}

// ── Enforcement Policy ────────────────────────────────────────────────────────

export class EnforcementPolicy {
  constructor(
    public readonly name: string,
    public readonly rules: Record<string, string[]>,
  ) {}

  enforce(card: CardLike, action: string): void {
    const required = this.rules[action];
    if (required === undefined) {
      throw new Error(
        `Unknown action '${action}' in policy '${this.name}'. ` +
          `Known actions: ${Object.keys(this.rules).join(", ")}`,
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
