/**
 * Carapace v0.2 — Card Expiry / TTL (TypeScript)
 *
 * Usage:
 *   import { makeExpiresAt, checkExpiry, isExpired, ExpiryStatus } from './expiry';
 *
 *   const expires = makeExpiresAt({ ttlHours: 24 });
 *   const status = checkExpiry(card);
 */

import type { CardLike } from './enforce';

// ── Types ────────────────────────────────────────────────────────────────────

export enum ExpiryStatus {
  VALID = 'valid',
  EXPIRED = 'expired',
  EXPIRING_SOON = 'expiring_soon',
  NO_EXPIRY = 'no_expiry',
}

export interface ExpiryCheckResult {
  passed: boolean;
  reason: string | null;
  expiresAt: string | null;
  status: ExpiryStatus;
  hoursRemaining?: number | null;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Create an ISO 8601 expires_at string for card registration.
 *
 * makeExpiresAt({ ttlHours: 24 })
 * makeExpiresAt({ ttlDays: 90 })
 * makeExpiresAt({ absolute: '2026-12-31T23:59:59Z' })
 */
export function makeExpiresAt(opts?: {
  ttlHours?: number;
  ttlDays?: number;
  absolute?: string | Date;
}): string | null {
  if (!opts) return null;

  if (opts.absolute !== undefined) {
    if (opts.absolute instanceof Date) {
      return opts.absolute.toISOString();
    }
    return opts.absolute;
  }

  const hours = opts.ttlHours ?? 0;
  const days = opts.ttlDays ?? 0;
  const totalMs = (hours * 3600 + days * 86400) * 1000;

  if (totalMs <= 0) {
    if (hours === 0 && days === 0) return null;
    throw new Error('TTL must be positive');
  }

  return new Date(Date.now() + totalMs).toISOString();
}

/** Parse an expires_at string to a Date, or null. */
export function parseExpiresAt(value: string | Date | null | undefined): Date | null {
  if (value == null) return null;
  if (value instanceof Date) return value;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Check a card's expiry status.
 *
 * @param warningThresholdMs - How far in advance to flag EXPIRING_SOON (default: 24h)
 * @param now - Override current time (for testing)
 */
export function checkExpiry(
  card: CardLike | { expires_at?: string | null },
  options?: {
    warningThresholdMs?: number;
    now?: Date;
  },
): ExpiryStatus {
  const raw = (card as any).expires_at ?? null;
  const expDate = parseExpiresAt(raw);

  if (!expDate) return ExpiryStatus.NO_EXPIRY;

  const now = options?.now ?? new Date();
  const threshold = options?.warningThresholdMs ?? 24 * 60 * 60 * 1000; // 24h

  if (now.getTime() > expDate.getTime()) return ExpiryStatus.EXPIRED;
  if (now.getTime() > expDate.getTime() - threshold) return ExpiryStatus.EXPIRING_SOON;
  return ExpiryStatus.VALID;
}

/** Quick boolean: is the card past its TTL? */
export function isExpired(
  card: CardLike | { expires_at?: string | null },
  now?: Date,
): boolean {
  return checkExpiry(card, { now }) === ExpiryStatus.EXPIRED;
}

/**
 * Time remaining in milliseconds. Null if no expiry.
 * Negative if already expired.
 */
export function timeRemaining(
  card: CardLike | { expires_at?: string | null },
  now?: Date,
): number | null {
  const raw = (card as any).expires_at ?? null;
  const expDate = parseExpiresAt(raw);
  if (!expDate) return null;
  return expDate.getTime() - (now ?? new Date()).getTime();
}

/**
 * Returns a result object for integration into verify().
 */
export function validateExpiryForVerify(
  card: CardLike | { expires_at?: string | null },
): ExpiryCheckResult {
  const status = checkExpiry(card);
  const expiresAt = (card as any).expires_at ?? null;

  if (status === ExpiryStatus.EXPIRED) {
    return { passed: false, reason: 'card_expired', expiresAt, status };
  }

  if (status === ExpiryStatus.EXPIRING_SOON) {
    const remaining = timeRemaining(card);
    return {
      passed: true,
      reason: null,
      expiresAt,
      status,
      hoursRemaining: remaining != null ? remaining / (1000 * 3600) : null,
    };
  }

  return { passed: true, reason: null, expiresAt, status };
}
