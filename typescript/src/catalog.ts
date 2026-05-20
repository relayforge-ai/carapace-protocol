/**
 * Carapace SDK v0.5.0 — Catalog Sync
 *
 * ETag-based ARIA catalog fetch and local gate-check helpers.
 * Fail-open pattern: when ARIA is unreachable, use the stale catalog + log.
 */

export interface CatalogEntry {
  id: string;
  name: string;
  description: string;
  endpoint_url: string;
  status: 'active' | 'suspended' | 'pending';
  clawmark_score: number;
  gate_pass: boolean;
  tier: string;
  safety_class: string;
  certification_tier: string;
  streaming_supported: boolean;
  clawmark_breakdown: Record<string, unknown>;
  scope_requirements: Record<string, unknown>;
}

export interface CatalogState {
  catalog: CatalogEntry[];
  total: number;
  etag: string;
  fetched_at: string;
}

export interface GateResult {
  passed: boolean;
  tool_id: string;
  gates_checked: string[];
  gates_failed: string[];
  details: Record<string, unknown>;
  blocked_by: string | null;
}

export interface FetchCatalogOptions {
  etag?: string;
  timeout?: number;
  apiKey?: string;
}

export interface GateCheckOptions {
  revokedIds?: Set<string>;
  scoreThreshold?: number;
  delegationValid?: boolean;
  trustGatesEnabled?: boolean;
}

/**
 * Fetch the ARIA catalog with ETag support.
 *
 * Returns `{ state: CatalogState, etag: string }` when the catalog changed,
 * or `{ state: null, etag: existingEtag }` on 304 Not Modified.
 *
 * Throws on network failure — caller must catch and fail-open.
 */
export async function fetchCatalog(
  ariaUrl: string,
  options: FetchCatalogOptions = {},
): Promise<{ state: CatalogState | null; etag: string | null }> {
  const { etag, timeout = 5000, apiKey } = options;
  const headers: Record<string, string> = {};
  if (etag) headers['If-None-Match'] = etag;
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  let resp: Response;
  try {
    resp = await fetch(`${ariaUrl.replace(/\/$/, '')}/aria/v1/catalog`, {
      headers,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (resp.status === 304) {
    return { state: null, etag: etag ?? null };
  }

  if (!resp.ok) {
    throw new Error(`ARIA catalog fetch failed: HTTP ${resp.status}`);
  }

  const data = (await resp.json()) as {
    catalog: CatalogEntry[];
    total: number;
    etag?: string;
  };

  const newEtag =
    resp.headers.get('etag')?.replace(/^"|"$/g, '') ?? data.etag ?? '';

  const state: CatalogState = {
    catalog: data.catalog ?? [],
    total: data.total ?? (data.catalog?.length ?? 0),
    etag: newEtag,
    fetched_at: new Date().toISOString(),
  };

  return { state, etag: newEtag };
}

/** Look up a tool by ID in a catalog snapshot. */
export function catalogGet(
  state: CatalogState,
  toolId: string,
): CatalogEntry | null {
  return state.catalog.find((e) => e.id === toolId) ?? null;
}

/** True when a tool is in the catalog with status='active'. */
export function catalogIsActive(state: CatalogState, toolId: string): boolean {
  const entry = catalogGet(state, toolId);
  return entry !== null && entry.status === 'active';
}

/**
 * Run five-gate pre-call verification against a local catalog snapshot.
 *
 * Gates (in order):
 *   1. catalog_membership — tool is in the catalog
 *   2. active_status      — tool is not suspended
 *   3. revocation_clear   — tool is not in the revoked set
 *   4. clawmark_gate      — composite score >= threshold (default 80)
 *   5. delegation_valid   — delegation is valid (only checked when provided)
 *
 * When `trustGatesEnabled=false`, all gates pass (observe-only mode).
 * When `state` is null (ARIA unreachable), fail-open — all gates pass with a warning.
 */
export function runGateCheck(
  toolId: string,
  state: CatalogState | null,
  options: GateCheckOptions = {},
): GateResult {
  const {
    revokedIds,
    scoreThreshold = 80,
    delegationValid,
    trustGatesEnabled = true,
  } = options;

  if (!trustGatesEnabled) {
    return {
      passed: true,
      tool_id: toolId,
      gates_checked: [],
      gates_failed: [],
      details: { mode: 'observe_only' },
      blocked_by: null,
    };
  }

  if (state === null) {
    return {
      passed: true,
      tool_id: toolId,
      gates_checked: [],
      gates_failed: [],
      details: { mode: 'fail_open', reason: 'aria_unreachable' },
      blocked_by: null,
    };
  }

  const gates_checked: string[] = [];
  const gates_failed: string[] = [];
  const details: Record<string, unknown> = {};

  // Gate 1 — catalog membership
  gates_checked.push('catalog_membership');
  const entry = catalogGet(state, toolId);
  if (!entry) {
    gates_failed.push('catalog_membership');
    details['catalog_membership'] = 'tool not in catalog';
    return { passed: false, tool_id: toolId, gates_checked, gates_failed, details, blocked_by: 'catalog_membership' };
  }

  // Gate 2 — active status
  gates_checked.push('active_status');
  if (entry.status !== 'active') {
    gates_failed.push('active_status');
    details['active_status'] = `status=${entry.status}`;
    return { passed: false, tool_id: toolId, gates_checked, gates_failed, details, blocked_by: 'active_status' };
  }

  // Gate 3 — revocation clear
  gates_checked.push('revocation_clear');
  if (revokedIds?.has(toolId)) {
    gates_failed.push('revocation_clear');
    details['revocation_clear'] = 'tool is in active revocation set';
    return { passed: false, tool_id: toolId, gates_checked, gates_failed, details, blocked_by: 'revocation_clear' };
  }

  // Gate 4 — Clawmark score
  gates_checked.push('clawmark_gate');
  if (entry.clawmark_score < scoreThreshold) {
    gates_failed.push('clawmark_gate');
    details['clawmark_gate'] = `score=${entry.clawmark_score} < threshold=${scoreThreshold}`;
    return { passed: false, tool_id: toolId, gates_checked, gates_failed, details, blocked_by: 'clawmark_gate' };
  }

  // Gate 5 — delegation validity (only when delegation is in play)
  if (delegationValid !== undefined) {
    gates_checked.push('delegation_valid');
    if (!delegationValid) {
      gates_failed.push('delegation_valid');
      details['delegation_valid'] = 'delegation token is expired or revoked';
      return { passed: false, tool_id: toolId, gates_checked, gates_failed, details, blocked_by: 'delegation_valid' };
    }
  }

  details['score'] = entry.clawmark_score;
  return { passed: true, tool_id: toolId, gates_checked, gates_failed, details, blocked_by: null };
}
