/**
 * Carapace v0.2 — Agent Card Versioning (TypeScript mirror of versioning.py)
 */

// ── Errors ────────────────────────────────────────────────────────────────────

export class VersionChainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VersionChainError";
  }
}

export class OwnerMismatchError extends VersionChainError {
  constructor(message: string) {
    super(message);
    this.name = "OwnerMismatchError";
  }
}

export class VersionSequenceError extends VersionChainError {
  constructor(message: string) {
    super(message);
    this.name = "VersionSequenceError";
  }
}

export class SupersedesNotFoundError extends VersionChainError {
  constructor(message: string) {
    super(message);
    this.name = "SupersedesNotFoundError";
  }
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface VersionEntry {
  card_id: string;
  version: number;
  supersedes: string | null;
  superseded_by: string | null;
  owner_public_key: string;
  created_at: string | null;
  status: string;
}

export interface VersionChainResult {
  entries: VersionEntry[];
  readonly length: number;
  readonly current: VersionEntry | null;
  readonly original: VersionEntry | null;
  isValid(): boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function entryFromCard(card: Record<string, unknown>): VersionEntry {
  const owner = (card.owner as Record<string, unknown>) ?? {};
  return {
    card_id: (card.id as string) ?? "",
    version: (card.version as number) ?? 1,
    supersedes: (card.supersedes as string | null) ?? null,
    superseded_by: (card.superseded_by as string | null) ?? null,
    owner_public_key: (owner.public_key as string) ?? "",
    created_at: (card.created_at as string | null) ?? null,
    status: (card.status as string) ?? "active",
  };
}

function makeChain(entries: VersionEntry[]): VersionChainResult {
  return {
    entries,
    get length() { return entries.length; },
    get current() {
      if (!entries.length) return null;
      return entries.reduce((a, b) => (a.version > b.version ? a : b));
    },
    get original() {
      if (!entries.length) return null;
      return entries.reduce((a, b) => (a.version < b.version ? a : b));
    },
    isValid() {
      try {
        validateVersionChain(entries);
        return true;
      } catch {
        return false;
      }
    },
  };
}

// ── Validation ────────────────────────────────────────────────────────────────

export function validateVersionChain(
  entries: Array<VersionEntry | Record<string, unknown>>,
): VersionChainResult {
  const normalized: VersionEntry[] = entries.map((e) =>
    "card_id" in e && typeof e.card_id === "string"
      ? (e as VersionEntry)
      : entryFromCard(e as Record<string, unknown>),
  );

  if (!normalized.length) return makeChain([]);

  normalized.sort((a, b) => a.version - b.version);

  const owners = new Set(normalized.map((e) => e.owner_public_key));
  if (owners.size > 1) {
    throw new OwnerMismatchError(
      `Version chain contains multiple owners. All versions must share the same owner key.`,
    );
  }

  for (let i = 0; i < normalized.length; i++) {
    if (normalized[i].version < 1) {
      throw new VersionSequenceError(
        `Version must be >= 1, got ${normalized[i].version} for card ${normalized[i].card_id}`,
      );
    }
    if (i > 0 && normalized[i].version <= normalized[i - 1].version) {
      throw new VersionSequenceError(
        `Version ${normalized[i].version} is not greater than previous version ${normalized[i - 1].version}`,
      );
    }
  }

  const originals = normalized.filter((e) => e.supersedes === null);
  if (originals.length !== 1) {
    throw new VersionChainError(
      `Expected exactly one original (supersedes=null), found ${originals.length}`,
    );
  }
  if (originals[0] !== normalized[0]) {
    throw new VersionChainError(
      "The original card (supersedes=null) must be the lowest version",
    );
  }

  const cardIdSet = new Set(normalized.map((e) => e.card_id));
  for (let i = 1; i < normalized.length; i++) {
    const actual = normalized[i].supersedes;
    const expectedPredecessor = normalized[i - 1].card_id;
    if (actual !== expectedPredecessor) {
      if (!cardIdSet.has(actual ?? "")) {
        throw new SupersedesNotFoundError(
          `Card ${normalized[i].card_id} (v${normalized[i].version}) supersedes ${actual}, which is not in the chain`,
        );
      }
    }
  }

  return makeChain(normalized);
}

// ── Registration helpers ──────────────────────────────────────────────────────

export function prepareVersionFields(
  supersedesCard?: Record<string, unknown> | null,
): { version: number; supersedes: string | null } {
  if (!supersedesCard) return { version: 1, supersedes: null };

  const oldVersion = (supersedesCard.version as number) ?? 1;
  const oldId = (supersedesCard.id as string) ?? null;
  return { version: oldVersion + 1, supersedes: oldId };
}

export function validateSupersedesRegistration(
  newOwnerKey: string,
  supersededCard: Record<string, unknown>,
): void {
  const owner = (supersededCard.owner as Record<string, unknown>) ?? {};
  const oldKey = (owner.public_key as string) ?? "";
  if (newOwnerKey !== oldKey) {
    throw new OwnerMismatchError(
      `Cannot supersede card owned by ${oldKey.slice(0, 16)}... with key ${newOwnerKey.slice(0, 16)}... — owner must match`,
    );
  }
}
