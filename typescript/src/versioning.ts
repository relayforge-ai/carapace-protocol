/**
 * Carapace v0.2 — Agent Card Versioning (TypeScript)
 *
 * Usage:
 *   import { validateVersionChain, prepareVersionFields } from './versioning';
 *
 *   const fields = prepareVersionFields(oldCard);
 *   const chain = validateVersionChain([v1, v2, v3]);
 */

// ── Types ────────────────────────────────────────────────────────────────────

export interface VersionedCard {
  id: string;
  version?: number;
  supersedes?: string | null;
  superseded_by?: string | null;
  owner?: { public_key: string };
  status?: string;
  created_at?: string | null;
}

export interface VersionEntry {
  cardId: string;
  version: number;
  supersedes: string | null;
  supersededBy: string | null;
  ownerPublicKey: string;
  createdAt: string | null;
  status: string;
}

// ── Errors ───────────────────────────────────────────────────────────────────

export class VersionChainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VersionChainError';
  }
}

export class OwnerMismatchError extends VersionChainError {
  constructor(message: string) {
    super(message);
    this.name = 'OwnerMismatchError';
  }
}

export class VersionSequenceError extends VersionChainError {
  constructor(message: string) {
    super(message);
    this.name = 'VersionSequenceError';
  }
}

export class SupersedesNotFoundError extends VersionChainError {
  constructor(message: string) {
    super(message);
    this.name = 'SupersedesNotFoundError';
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function toEntry(card: VersionedCard): VersionEntry {
  return {
    cardId: card.id,
    version: card.version ?? 1,
    supersedes: card.supersedes ?? null,
    supersededBy: card.superseded_by ?? null,
    ownerPublicKey: card.owner?.public_key ?? '',
    createdAt: card.created_at ?? null,
    status: card.status ?? 'active',
  };
}

// ── Version Chain ────────────────────────────────────────────────────────────

export interface VersionChain {
  entries: VersionEntry[];
  current: VersionEntry | null;
  original: VersionEntry | null;
  length: number;
  isValid: boolean;
}

/**
 * Validate that a set of cards forms a proper version chain.
 *
 * Checks:
 * 1. Same owner across all versions
 * 2. Monotonically increasing version numbers
 * 3. Supersedes references point to valid predecessors
 * 4. Exactly one original (supersedes = null)
 */
export function validateVersionChain(cards: VersionedCard[]): VersionChain {
  if (cards.length === 0) {
    return { entries: [], current: null, original: null, length: 0, isValid: true };
  }

  const entries = cards.map(toEntry).sort((a, b) => a.version - b.version);

  // Check single owner
  const owners = new Set(entries.map((e) => e.ownerPublicKey));
  if (owners.size > 1) {
    throw new OwnerMismatchError(
      `Version chain contains multiple owners: ${[...owners].join(', ')}. All versions must share the same owner key.`,
    );
  }

  // Check version sequence
  for (let i = 0; i < entries.length; i++) {
    if (entries[i].version < 1) {
      throw new VersionSequenceError(
        `Version must be >= 1, got ${entries[i].version} for card ${entries[i].cardId}`,
      );
    }
    if (i > 0 && entries[i].version <= entries[i - 1].version) {
      throw new VersionSequenceError(
        `Version ${entries[i].version} is not greater than previous version ${entries[i - 1].version}`,
      );
    }
  }

  // Check supersedes chain
  const originals = entries.filter((e) => e.supersedes === null);
  if (originals.length !== 1) {
    throw new VersionChainError(
      `Expected exactly one original (supersedes=null), found ${originals.length}`,
    );
  }
  if (originals[0] !== entries[0]) {
    throw new VersionChainError(
      'The original card (supersedes=null) must be the lowest version',
    );
  }

  const cardIdSet = new Set(entries.map((e) => e.cardId));
  for (let i = 1; i < entries.length; i++) {
    const target = entries[i].supersedes;
    if (target && !cardIdSet.has(target)) {
      throw new SupersedesNotFoundError(
        `Card ${entries[i].cardId} (v${entries[i].version}) supersedes ${target}, which is not in the chain`,
      );
    }
  }

  return {
    entries,
    current: entries[entries.length - 1],
    original: entries[0],
    length: entries.length,
    isValid: true,
  };
}

// ── Registration Helpers ─────────────────────────────────────────────────────

/**
 * Prepare version and supersedes fields for a registration call.
 *
 * prepareVersionFields()          → { version: 1, supersedes: null }
 * prepareVersionFields(oldCard)   → { version: 2, supersedes: 'old-uuid' }
 */
export function prepareVersionFields(
  supersedesCard?: VersionedCard | null,
): { version: number; supersedes: string | null } {
  if (!supersedesCard) {
    return { version: 1, supersedes: null };
  }
  return {
    version: (supersedesCard.version ?? 1) + 1,
    supersedes: supersedesCard.id,
  };
}

/**
 * Pre-registration check: verify the new card's owner matches the superseded card.
 */
export function validateSupersedesRegistration(
  newOwnerKey: string,
  supersededCard: VersionedCard,
): void {
  const oldKey = supersededCard.owner?.public_key ?? '';
  if (newOwnerKey !== oldKey) {
    throw new OwnerMismatchError(
      `Cannot supersede card owned by ${oldKey.slice(0, 16)}... with key ${newOwnerKey.slice(0, 16)}... — owner must match`,
    );
  }
}
