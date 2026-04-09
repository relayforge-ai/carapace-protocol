/**
 * Carapace v0.2 — Card Expiry / TTL (TypeScript mirror of expiry.py)
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export enum ExpiryStatus {
  VALID = "valid",
  EXPIRED = "expired",
  EXPIRING_SOON = "expiring_soon",
  NO_EXPIRY = "no_expiry",
}

export interface ExpiryCheckResult {
  passed: boolean;
  reason: string | null;
  expires_at: string | null | undefined;
  status: string;
  hours_remaining?: number | null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function parseExpiresAt(value: unknown): Date | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return isNaN(value.getTime()) ? null : value;
  if (typeof value === "string") {
    const d = new Date(value);
    return isNaN(d.getTime()) ? null : d;
  }
  return null;
}

export function makeExpiresAt(opts: {
  ttlHours?: number;
  ttlDays?: number;
  absolute?: Date | string;
}): string | null {
  const { ttlHours, ttlDays, absolute } = opts;

  if (absolute !== undefined) {
    if (typeof absolute === "string") return absolute;
    if (absolute instanceof Date) return absolute.toISOString();
    throw new TypeError("absolute must be a Date or string");
  }

  if (ttlHours !== undefined || ttlDays !== undefined) {
    const ms =
      ((ttlHours ?? 0) * 3600 + (ttlDays ?? 0) * 86400) * 1000;
    if (ms <= 0) throw new Error("TTL must be positive");
    return new Date(Date.now() + ms).toISOString();
  }

  return null;
}

export function checkExpiry(
  card: { expires_at?: string | null } | Record<string, unknown>,
  opts: { warningThresholdMs?: number; now?: Date } = {},
): ExpiryStatus {
  const raw =
    (card as Record<string, unknown>).expires_at ??
    (card as { expires_at?: unknown }).expires_at;

  const expiresDt = parseExpiresAt(raw);
  if (!expiresDt) return ExpiryStatus.NO_EXPIRY;

  const now = opts.now ?? new Date();
  const warningMs = opts.warningThresholdMs ?? 24 * 3600 * 1000;

  if (now > expiresDt) return ExpiryStatus.EXPIRED;
  if (now > new Date(expiresDt.getTime() - warningMs)) return ExpiryStatus.EXPIRING_SOON;
  return ExpiryStatus.VALID;
}

export function isExpired(
  card: { expires_at?: string | null },
  opts: { now?: Date } = {},
): boolean {
  return checkExpiry(card, opts) === ExpiryStatus.EXPIRED;
}

export function timeRemaining(
  card: { expires_at?: string | null },
  opts: { now?: Date } = {},
): number | null {
  const expiresDt = parseExpiresAt(card.expires_at);
  if (!expiresDt) return null;
  const now = opts.now ?? new Date();
  return expiresDt.getTime() - now.getTime(); // ms
}

export function validateExpiryForVerify(
  card: { expires_at?: string | null },
  opts: { now?: Date } = {},
): ExpiryCheckResult {
  const status = checkExpiry(card, opts);
  const expiresAt = card.expires_at;

  if (status === ExpiryStatus.EXPIRED) {
    return {
      passed: false,
      reason: "card_expired",
      expires_at: expiresAt,
      status: "expired",
    };
  }

  if (status === ExpiryStatus.EXPIRING_SOON) {
    const remaining = timeRemaining(card, opts);
    return {
      passed: true,
      reason: null,
      expires_at: expiresAt,
      status: "expiring_soon",
      hours_remaining: remaining !== null ? remaining / 3_600_000 : null,
    };
  }

  return {
    passed: true,
    reason: null,
    expires_at: expiresAt,
    status: status,
  };
}
