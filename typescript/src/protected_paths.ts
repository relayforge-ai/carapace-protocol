/**
 * Carapace v0.3 — Protected Path Guard (TypeScript)
 *
 * Prevents prompt-injection attacks from rewriting identity, policy, config,
 * and other runtime-critical files.  Writes to protected paths are blocked by
 * default and require explicit human-issued scoped approval to proceed.
 *
 * @example
 * ```ts
 * import { checkProtectedWrite, ProtectedWriteBlocked } from './protected_paths';
 *
 * // Throws ProtectedWriteBlocked for protected targets
 * checkProtectedWrite('IDENTITY.md');
 *
 * // With valid human-issued approval
 * const approval = new ProtectedWriteApproval({
 *   gateWord: 'SHELDON-ALPHA',
 *   pathScope: 'IDENTITY.md',
 *   issuedBy: 'human',
 *   expiresAt: new Date(Date.now() + 3600_000).toISOString(),
 * });
 * const entry = checkProtectedWrite('IDENTITY.md', { approval });
 * // entry is an AuditLogEntry — persist it
 * ```
 *
 * Authorization rules:
 * - `issuedBy` must be `"human"` — parent/subagent/tool/file/browser output
 *   cannot authorize a protected write.
 * - The approval must carry a non-empty gate word.
 * - The approval must not have expired.
 * - The approval's `pathScope` must cover the target path.
 * - Every blocked or approved write is recorded in the audit log.
 */

import * as crypto from 'crypto';

// ── Protected path patterns ──────────────────────────────────────────────────
// Patterns support simple glob syntax (fnmatch-style):
//   *  matches any characters within a single path segment
//   ** matches any characters across multiple segments (treated as *)

export const DEFAULT_PROTECTED_PATTERNS: readonly string[] = [
  // Identity & persona
  'IDENTITY.md',
  'SYSTEM.md',
  'AGENT.md',
  // Runtime configuration
  'openclaw.json',
  // Environment / secrets
  '.env',
  '.env.*',
  'secrets/*',
  'secrets/**',
  // Config directories
  'config/*',
  'config/**',
  // Policy directories
  'policies/*',
  'policies/**',
  // Runtime directories
  'runtime/*',
  'runtime/**',
  // Model routing
  'model_routing.json',
  'model_routing.yaml',
  'model_routing.yml',
  // Tool permissions
  'tool_permissions.json',
  'tool_permissions.yaml',
  'tool_permissions.yml',
  // Memory / behaviour policies
  'memory_policy.json',
  'memory_policy.yaml',
  'memory_policy.yml',
];

/**
 * Sources from which a protected-write approval may NOT originate.
 * Any other string (e.g. `"human"`) is accepted.
 */
export const UNAUTHORIZED_SOURCES: ReadonlySet<string> = new Set([
  'agent',
  'subagent',
  'tool',
  'file',
  'browser_output',
  'llm',
  'model',
]);

// ── Errors ────────────────────────────────────────────────────────────────────

export class ProtectedPathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtectedPathError';
  }
}

export class ProtectedWriteBlocked extends ProtectedPathError {
  readonly path: string;
  readonly reason: string;
  readonly patternMatched: string | null;

  constructor(path: string, reason: string, patternMatched: string | null = null) {
    const detail = patternMatched ? ` (matched pattern: ${JSON.stringify(patternMatched)})` : '';
    super(`Protected write blocked for ${JSON.stringify(path)}${detail}: ${reason}`);
    this.name = 'ProtectedWriteBlocked';
    this.path = path;
    this.reason = reason;
    this.patternMatched = patternMatched;
  }
}

export class ApprovalSourceForbidden extends ProtectedPathError {
  readonly source: string;

  constructor(source: string) {
    super(
      `Protected-write approval cannot be issued by source ${JSON.stringify(source)}. ` +
      `Only 'human' is a valid authorization source.`
    );
    this.name = 'ApprovalSourceForbidden';
    this.source = source;
  }
}

// ── Data models ───────────────────────────────────────────────────────────────

export interface ProtectedWriteApprovalOpts {
  /** A non-empty secret phrase that identifies this approval. */
  gateWord: string;
  /** Exact path or glob pattern (fnmatch-style) this approval covers. */
  pathScope: string;
  /** Must be `"human"`. Any source in UNAUTHORIZED_SOURCES is rejected. */
  issuedBy: string;
  /** ISO 8601 expiry (required). */
  expiresAt: string;
  /** Optional human-readable description for the audit trail. */
  note?: string;
  /** Unique ID — auto-generated if omitted. */
  tokenId?: string;
}

/**
 * A scoped, time-limited human authorization for a single protected write.
 */
export class ProtectedWriteApproval {
  readonly gateWord: string;
  readonly pathScope: string;
  readonly issuedBy: string;
  readonly expiresAt: string;
  readonly note: string;
  readonly tokenId: string;

  constructor(opts: ProtectedWriteApprovalOpts) {
    if (!opts.gateWord.trim()) {
      throw new Error('gateWord must not be empty');
    }
    if (!opts.pathScope.trim()) {
      throw new Error('pathScope must not be empty');
    }
    if (!opts.expiresAt) {
      throw new Error('expiresAt is required on ProtectedWriteApproval');
    }
    if (UNAUTHORIZED_SOURCES.has(opts.issuedBy)) {
      throw new ApprovalSourceForbidden(opts.issuedBy);
    }
    if (!opts.issuedBy.trim()) {
      throw new Error('issuedBy must not be empty');
    }

    this.gateWord = opts.gateWord;
    this.pathScope = opts.pathScope;
    this.issuedBy = opts.issuedBy;
    this.expiresAt = opts.expiresAt;
    this.note = opts.note ?? '';
    this.tokenId = opts.tokenId ?? crypto.randomBytes(16).toString('hex');
  }

  get isExpired(): boolean {
    const dt = new Date(this.expiresAt);
    if (isNaN(dt.getTime())) return true;
    return Date.now() > dt.getTime();
  }

  /**
   * Return true when *path* matches this approval's pathScope.
   * Supports fnmatch-style globs (`*` and `**`).
   */
  coversPath(path: string): boolean {
    return fnmatch(path.replace(/\\/g, '/'), this.pathScope.replace(/\\/g, '/'));
  }
}

export interface AuditLogEntryData {
  entryId: string;
  timestamp: string;
  path: string;
  operation: string;
  outcome: 'blocked' | 'approved';
  reason: string;
  patternMatched: string | null;
  approvalTokenId: string | null;
  approvalGateWordPrefix: string | null;
  issuedBy: string | null;
}

type AuditLogEntryInput =
  Omit<
    AuditLogEntryData,
    | 'entryId'
    | 'timestamp'
    | 'patternMatched'
    | 'approvalTokenId'
    | 'approvalGateWordPrefix'
    | 'issuedBy'
  > &
  Partial<
    Pick<
      AuditLogEntryData,
      | 'entryId'
      | 'timestamp'
      | 'patternMatched'
      | 'approvalTokenId'
      | 'approvalGateWordPrefix'
      | 'issuedBy'
    >
  >;

/**
 * An immutable record of a protected-write check outcome.
 * Every call to `checkProtectedWrite` produces one of these.
 */
export class AuditLogEntry {
  readonly entryId: string;
  readonly timestamp: string;
  readonly path: string;
  readonly operation: string;
  readonly outcome: 'blocked' | 'approved';
  readonly reason: string;
  readonly patternMatched: string | null;
  readonly approvalTokenId: string | null;
  readonly approvalGateWordPrefix: string | null;
  readonly issuedBy: string | null;

  constructor(data: AuditLogEntryInput) {
    this.entryId = data.entryId ?? crypto.randomBytes(8).toString('hex');
    this.timestamp = data.timestamp ?? new Date().toISOString();
    this.path = data.path;
    this.operation = data.operation;
    this.outcome = data.outcome;
    this.reason = data.reason;
    this.patternMatched = data.patternMatched ?? null;
    this.approvalTokenId = data.approvalTokenId ?? null;
    this.approvalGateWordPrefix = data.approvalGateWordPrefix ?? null;
    this.issuedBy = data.issuedBy ?? null;
  }

  asDict(): AuditLogEntryData {
    return {
      entryId: this.entryId,
      timestamp: this.timestamp,
      path: this.path,
      operation: this.operation,
      outcome: this.outcome,
      reason: this.reason,
      patternMatched: this.patternMatched,
      approvalTokenId: this.approvalTokenId,
      approvalGateWordPrefix: this.approvalGateWordPrefix,
      issuedBy: this.issuedBy,
    };
  }
}

// ── In-memory audit log ───────────────────────────────────────────────────────

const _auditLog: AuditLogEntry[] = [];
const _MAX_AUDIT_LOG = 10_000;
const _auditSinks: Array<(entry: AuditLogEntry) => void> = [];

function _appendAudit(entry: AuditLogEntry): void {
  _auditLog.push(entry);
  if (_auditLog.length > _MAX_AUDIT_LOG) {
    _auditLog.shift();
  }
  for (const sink of _auditSinks) {
    try {
      sink(entry);
    } catch {
      // Sinks must not interrupt the guard
    }
  }
}

/**
 * Register a callback that will be called with each AuditLogEntry.
 * The callback must not throw; any exception is silently swallowed.
 */
export function registerAuditSink(fn: (entry: AuditLogEntry) => void): void {
  _auditSinks.push(fn);
}

/** Return a snapshot of the audit log, most recent first. */
export function getAuditLog(): AuditLogEntry[] {
  return [..._auditLog].reverse();
}

/** Clear the in-memory audit log. Useful between tests. */
export function clearAuditLog(): void {
  _auditLog.length = 0;
}

// ── fnmatch helper ────────────────────────────────────────────────────────────

/**
 * Simple fnmatch-style pattern match.
 * `*` and `**` both match any sequence of characters (cross-segment for `**`).
 */
function fnmatch(path: string, pattern: string): boolean {
  // Escape regex special chars except * which we handle specially
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '.+')   // ** → one or more chars
    .replace(/\*/g, '[^/]*');  // * → any chars within segment
  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(path);
}

// ── Core guard functions ──────────────────────────────────────────────────────

function matchingPattern(path: string, patterns: readonly string[]): string | null {
  const normalised = path.replace(/\\/g, '/');
  const basename = normalised.includes('/') ? normalised.slice(normalised.lastIndexOf('/') + 1) : normalised;

  for (const pattern of patterns) {
    if (fnmatch(normalised, pattern)) return pattern;
    if (fnmatch(basename, pattern)) return pattern;
  }
  return null;
}

/**
 * Return true if *path* matches any protected pattern.
 */
export function isProtectedPath(
  path: string,
  { extraPatterns = [] }: { extraPatterns?: readonly string[] } = {},
): boolean {
  return matchingPattern(path, [...DEFAULT_PROTECTED_PATTERNS, ...extraPatterns]) !== null;
}

export interface CheckProtectedWriteOptions {
  /** Human-readable operation label (default: `"write"`). */
  operation?: string;
  /** A ProtectedWriteApproval issued by a human. */
  approval?: ProtectedWriteApproval;
  /** Additional protected patterns beyond the defaults. */
  extraPatterns?: readonly string[];
}

/**
 * Gate a write/edit/delete operation on *path*.
 *
 * Throws `ProtectedWriteBlocked` if the path is protected and no valid
 * approval is supplied.  Returns an `AuditLogEntry` on success.
 */
export function checkProtectedWrite(
  path: string,
  opts: CheckProtectedWriteOptions = {},
): AuditLogEntry {
  const { operation = 'write', approval, extraPatterns = [] } = opts;
  const allPatterns = [...DEFAULT_PROTECTED_PATTERNS, ...extraPatterns];
  const matched = matchingPattern(path, allPatterns);

  // ── Not a protected path ──────────────────────────────────────────────────
  if (matched === null) {
    const entry = new AuditLogEntry({
      path,
      operation,
      outcome: 'approved',
      reason: 'path_not_protected',
    });
    _appendAudit(entry);
    return entry;
  }

  // ── Protected path — validate approval ────────────────────────────────────
  function block(reason: string): never {
    const entry = new AuditLogEntry({
      path,
      operation,
      outcome: 'blocked',
      reason,
      patternMatched: matched,
      approvalTokenId: approval?.tokenId ?? null,
      issuedBy: approval?.issuedBy ?? null,
    });
    _appendAudit(entry);
    throw new ProtectedWriteBlocked(path, reason, matched);
  }

  if (!approval) {
    block('no_approval_provided');
  }

  if (UNAUTHORIZED_SOURCES.has(approval!.issuedBy)) {
    block('approval_source_forbidden');
  }

  if (approval!.isExpired) {
    block('approval_expired');
  }

  if (!approval!.coversPath(path)) {
    block('approval_scope_mismatch');
  }

  // ── Approved ──────────────────────────────────────────────────────────────
  const gatePrefix = approval!.gateWord.slice(0, 4) || null;
  const entry = new AuditLogEntry({
    path,
    operation,
    outcome: 'approved',
    reason: 'valid_approval',
    patternMatched: matched,
    approvalTokenId: approval!.tokenId,
    approvalGateWordPrefix: gatePrefix,
    issuedBy: approval!.issuedBy,
  });
  _appendAudit(entry);
  return entry;
}
