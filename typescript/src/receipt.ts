/**
 * Carapace SDK v0.5.0 — Signed Tool-Call Receipts
 *
 * Receipts provide a cryptographic audit trail for tool calls.
 * They store SHA-256 hashes only — no PII or raw content.
 *
 * Posting receipts to ARIA is best-effort. A failed post MUST NOT
 * block the tool call.
 */

export interface ReceiptPayload {
  tool_id: string;
  agent_id: string | null;
  call_hash: string;
  args_hash: string;
  result_hash: string | null;
  signature: string | null;
  public_key: string | null;
  status: 'ok' | 'error';
}

export interface CreateReceiptOptions {
  agentId?: string;
  status?: 'ok' | 'error';
  /** Ed25519 key pair from `crypto.subtle.generateKey`. Public key is extracted automatically. */
  keyPair?: { privateKey: CryptoKey; publicKey: CryptoKey };
}

export interface PostReceiptOptions {
  apiKey?: string;
  timeout?: number;
}

/** Recursively sort object keys for canonical JSON serialization (RFC 8785 key order). */
function sortKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = sortKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * SHA-256 of deterministic JSON string (keys sorted recursively).
 * Uses SubtleCrypto (available in browser and Node 18+).
 */
async function sha256Json(obj: unknown): Promise<string> {
  const canonical = JSON.stringify(sortKeys(obj));
  const buf = new TextEncoder().encode(canonical);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Create a signed tool-call receipt.
 *
 * When `keyPair` is provided (Ed25519 CryptoKeyPair from `crypto.subtle.generateKey`),
 * the receipt is signed using WebCrypto Ed25519 and `public_key` is populated.
 * Requires Chrome 113+, Firefox 126+, Safari 17+, or Node 20+.
 *
 * The returned object is ready to POST to /aria/v1/receipts.
 */
export async function createReceipt(
  toolId: string,
  args: unknown,
  result: unknown = null,
  options: CreateReceiptOptions = {},
): Promise<ReceiptPayload> {
  const { agentId = null, status = 'ok', keyPair } = options;

  const argsHash = await sha256Json(args);
  const resultHash = result !== null ? await sha256Json(result) : null;
  const ts = new Date().toISOString();

  const callHashInput = `${toolId}:${argsHash}:${resultHash ?? ''}:${ts}`;
  const callHashBuf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(callHashInput),
  );
  const callHash = Array.from(new Uint8Array(callHashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  let signature: string | null = null;
  let publicKeyHex: string | null = null;

  if (keyPair) {
    const sigBuf = await crypto.subtle.sign(
      'Ed25519',
      keyPair.privateKey,
      new TextEncoder().encode(callHash),
    );
    signature = Array.from(new Uint8Array(sigBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const pkBuf = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    publicKeyHex = Array.from(new Uint8Array(pkBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  return {
    tool_id: toolId,
    agent_id: agentId,
    call_hash: callHash,
    args_hash: argsHash,
    result_hash: resultHash,
    signature,
    public_key: publicKeyHex,
    status,
  };
}

/**
 * Verify a receipt's Ed25519 signature via WebCrypto.
 * Returns false (not throws) on any failure.
 */
export async function verifyReceipt(
  receipt: ReceiptPayload,
  publicKeyHex?: string,
): Promise<boolean> {
  const sig = receipt.signature;
  const pk = publicKeyHex ?? receipt.public_key;
  const callHash = receipt.call_hash;

  if (!sig || !pk || !callHash) return false;

  try {
    const sigBytes = Uint8Array.from(sig.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
    const pkBytes = Uint8Array.from(pk.match(/.{2}/g)!.map((b) => parseInt(b, 16)));

    const key = await crypto.subtle.importKey(
      'raw',
      pkBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      'Ed25519',
      key,
      sigBytes,
      new TextEncoder().encode(callHash),
    );
  } catch {
    return false;
  }
}

/**
 * Fire-and-forget receipt post. Returns true on success, false on any error.
 * NEVER throws — a failed post MUST NOT block the tool call.
 */
export async function postReceipt(
  ariaUrl: string,
  receipt: ReceiptPayload,
  options: PostReceiptOptions = {},
): Promise<boolean> {
  const { apiKey, timeout = 3000 } = options;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

    let resp: Response;
    try {
      resp = await fetch(`${ariaUrl.replace(/\/$/, '')}/aria/v1/receipts`, {
        method: 'POST',
        headers,
        body: JSON.stringify(receipt),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    return resp.ok;
  } catch {
    return false;
  }
}
