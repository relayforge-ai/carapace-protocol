/** Version 2 receipts: authenticated envelope, not proof that an action occurred. */
import { DOMAIN, FIELDS, contentHash, receiptPayload } from './receipt-protocol';

export interface ReceiptPayload {
  receipt_version?: '1' | '2';
  domain?: string;
  receipt_id?: string;
  issued_at?: string;
  tool_id: string;
  tool_version?: string | null;
  agent_id: string | null;
  authorization_id?: string | null;
  call_hash: string;
  args_hash: string;
  result_hash: string | null;
  signature: string | null;
  public_key: string | null;
  status: 'ok' | 'error';
}
export interface ReceiptV2Payload extends ReceiptPayload {
  receipt_version: '2'; domain: string; receipt_id: string; issued_at: string;
  tool_version: string | null; authorization_id: string | null;
}
export interface CreateReceiptOptions {
  agentId?: string;
  status?: 'ok' | 'error';
  keyPair?: { privateKey: CryptoKey; publicKey: CryptoKey };
  toolVersion?: string;
  authorizationId?: string;
}
export interface PostReceiptOptions { apiKey?: string; timeout?: number; }

/** Persist and retry the SAME returned object; JSON-only inputs use RFC 8785. */
export async function createReceipt(
  toolId: string, args: unknown, result: unknown = null, options: CreateReceiptOptions = {},
): Promise<ReceiptV2Payload> {
  const { agentId = null, status = 'ok', keyPair, toolVersion = null, authorizationId = null } = options;
  const receipt: ReceiptV2Payload = {
    receipt_version: '2', domain: DOMAIN, receipt_id: crypto.randomUUID(), issued_at: new Date().toISOString(),
    tool_id: toolId, tool_version: toolVersion, agent_id: agentId, authorization_id: authorizationId,
    args_hash: await contentHash(args), result_hash: result !== null ? await contentHash(result) : null,
    public_key: null, signature: null, call_hash: '', status,
  };
  if (keyPair) {
    const bytes = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    receipt.public_key = Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  }
  receipt.call_hash = await contentHash(Object.fromEntries(FIELDS.map(field => [field, receipt[field]])));
  if (keyPair) {
    const bytes = await crypto.subtle.sign('Ed25519', keyPair.privateKey, new TextEncoder().encode(receipt.call_hash));
    receipt.signature = Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  }
  receiptPayload(receipt as unknown as Record<string, unknown>);
  if (keyPair && !await verifyReceipt(receipt)) throw new Error('Mismatched signing key pair');
  return receipt;
}

/** Legacy/unsigned receipts return false. Pin a trusted key to establish issuer identity. */
export async function verifyReceipt(receipt: unknown, publicKeyHex?: string): Promise<boolean> {
  try {
    if (!receipt || typeof receipt !== 'object') return false;
    const data = receipt as Record<string, unknown>;
    const payload = receiptPayload(data);
    if (!data.signature || (publicKeyHex !== undefined && publicKeyHex !== data.public_key)) return false;
    if (await contentHash(payload) !== data.call_hash) return false;
    const pk = Uint8Array.from((data.public_key as string).match(/.{2}/g)!, b => parseInt(b, 16));
    const sig = Uint8Array.from((data.signature as string).match(/.{2}/g)!, b => parseInt(b, 16));
    const key = await crypto.subtle.importKey('raw', pk, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, sig, new TextEncoder().encode(data.call_hash as string));
  } catch { return false; }
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
    if (!resp.ok) return false;
    if (receipt.receipt_version !== '2') return true;
    const ack = await resp.json() as { verification_status?: string; ok?: boolean };
    return ack.ok === true && ack.verification_status === (receipt.signature ? 'verified_v2' : 'unsigned_v2');
    } finally { clearTimeout(timer); }
  } catch {
    return false;
  }
}
