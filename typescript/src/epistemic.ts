/**
 * Carapace v0.4 — Epistemic Tracking (TypeScript)
 *
 * Tamper-evident, append-only provenance log for agent decisions.
 * The PSM paper trail for the agentic web.
 */

import { createHash } from 'crypto';

// ── Types ────────────────────────────────────────────────────────────────────

export enum ConfidenceLevel {
  VERIFIED = 'verified',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  UNVERIFIED = 'unverified',
  HUMAN_OVERRIDE = 'human_override',
}

export interface Source {
  agent_id: string;
  card_signature?: string | null;
  data_hash?: string | null;
  timestamp?: string | null;
  description?: string | null;
}

export interface EpistemicEntry {
  sequence: number;
  agent_id: string;
  action: string;
  sources: Source[];
  confidence: number;
  confidence_level: ConfidenceLevel;
  reasoning: string | null;
  timestamp: string;
  data_hash: string;
  prev_hash: string;
  entry_hash: string;
  delegation_id: string | null;
  metadata: Record<string, any>;
}

// ── Hashing ──────────────────────────────────────────────────────────────────

function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

async function sha256(data: string): Promise<string> {
  return sha256Hex(data);
}

function confidenceToLevel(c: number): ConfidenceLevel {
  if (c >= 0.95) return ConfidenceLevel.VERIFIED;
  if (c >= 0.8) return ConfidenceLevel.HIGH;
  if (c >= 0.6) return ConfidenceLevel.MEDIUM;
  if (c >= 0.3) return ConfidenceLevel.LOW;
  return ConfidenceLevel.UNVERIFIED;
}

// ── Hash Utility ─────────────────────────────────────────────────────────────

export async function hashData(data: string): Promise<string> {
  return sha256(data);
}

// ── Epistemic Log ────────────────────────────────────────────────────────────

const GENESIS_SEED = 'carapace:epistemic:genesis:v0.4';
export const GENESIS_HASH = sha256Hex(GENESIS_SEED);

function entryDataPayload(entry: {
  agent_id: string;
  action: string;
  confidence: number;
  delegation_id: string | null;
  reasoning: string | null;
  sources: Source[];
  timestamp: string;
}): string {
  return JSON.stringify({
    agent_id: entry.agent_id,
    action: entry.action,
    confidence: entry.confidence,
    delegation_id: entry.delegation_id,
    reasoning: entry.reasoning,
    sources: entry.sources.map((s) => ({
      agent_id: s.agent_id,
      card_signature: s.card_signature ?? null,
      data_hash: s.data_hash ?? null,
      description: s.description ?? null,
      timestamp: s.timestamp ?? entry.timestamp,
    })),
    timestamp: entry.timestamp,
  });
}

export class EpistemicLog {
  readonly agentId: string;
  private _entries: EpistemicEntry[] = [];
  private _genesisHash: string = GENESIS_HASH;
  private _initialized: boolean = false;

  constructor(agentId: string, entries?: EpistemicEntry[]) {
    this.agentId = agentId;
    this._entries = entries ?? [];
  }

  private async ensureInit(): Promise<void> {
    if (!this._initialized) {
      this._genesisHash = GENESIS_HASH;
      this._initialized = true;
    }
  }

  get entries(): EpistemicEntry[] { return [...this._entries]; }
  get length(): number { return this._entries.length; }

  async latestHash(): Promise<string> {
    await this.ensureInit();
    return this._entries.length > 0
      ? this._entries[this._entries.length - 1].entry_hash
      : this._genesisHash;
  }

  async record(opts: {
    action: string;
    sources?: Source[];
    confidence?: number;
    confidenceLevel?: ConfidenceLevel;
    reasoning?: string;
    delegationId?: string;
    metadata?: Record<string, any>;
    timestamp?: string;
  }): Promise<EpistemicEntry> {
    await this.ensureInit();

    const {
      action, sources = [], confidence = 0.5,
      reasoning = null, delegationId = null, metadata = {},
    } = opts;
    const ts = opts.timestamp ?? new Date().toISOString();
    const level = opts.confidenceLevel ?? confidenceToLevel(confidence);
    const sequence = this._entries.length + 1;
    const prevHash = await this.latestHash();
    const normalizedSources = sources.map((s) => ({
      agent_id: s.agent_id,
      card_signature: s.card_signature ?? null,
      data_hash: s.data_hash ?? null,
      description: s.description ?? null,
      timestamp: s.timestamp ?? ts,
    }));

    const dataPayload = entryDataPayload({
      agent_id: this.agentId,
      action,
      confidence,
      delegation_id: delegationId,
      reasoning,
      sources: normalizedSources,
      timestamp: ts,
    });

    const dataHash = await sha256(dataPayload);
    const entryHash = await sha256(dataHash + prevHash);

    const entry: EpistemicEntry = {
      sequence, agent_id: this.agentId, action, sources: normalizedSources,
      confidence, confidence_level: level, reasoning, timestamp: ts,
      data_hash: dataHash, prev_hash: prevHash, entry_hash: entryHash,
      delegation_id: delegationId, metadata,
    };

    this._entries.push(entry);
    return entry;
  }

  async verifyIntegrity(): Promise<{ valid: boolean; brokenAt: number | null }> {
    await this.ensureInit();
    if (this._entries.length === 0) return { valid: true, brokenAt: null };

    let expectedPrev = this._genesisHash;
    for (const entry of this._entries) {
      if (entry.prev_hash !== expectedPrev) {
        return { valid: false, brokenAt: entry.sequence };
      }
      const recomputedData = await sha256(entryDataPayload(entry));
      if (recomputedData !== entry.data_hash) {
        return { valid: false, brokenAt: entry.sequence };
      }
      const recomputedEntry = await sha256(entry.data_hash + entry.prev_hash);
      if (recomputedEntry !== entry.entry_hash) {
        return { valid: false, brokenAt: entry.sequence };
      }
      expectedPrev = entry.entry_hash;
    }
    return { valid: true, brokenAt: null };
  }

  async exportAuditTrail(): Promise<Record<string, any>> {
    const { valid, brokenAt } = await this.verifyIntegrity();
    return {
      agent_id: this.agentId,
      entry_count: this.length,
      integrity_valid: valid,
      broken_at_sequence: brokenAt,
      latest_hash: await this.latestHash(),
      entries: this._entries,
      exported_at: new Date().toISOString(),
    };
  }

  query(filters: {
    action?: string;
    sourceAgentId?: string;
    minConfidence?: number;
    delegationId?: string;
  }): EpistemicEntry[] {
    let results = this._entries;
    if (filters.action) results = results.filter((e) => e.action === filters.action);
    if (filters.sourceAgentId) {
      results = results.filter((e) =>
        e.sources.some((s) => s.agent_id === filters.sourceAgentId));
    }
    if (filters.minConfidence != null) {
      results = results.filter((e) => e.confidence >= filters.minConfidence!);
    }
    if (filters.delegationId) {
      results = results.filter((e) => e.delegation_id === filters.delegationId);
    }
    return results;
  }
}
