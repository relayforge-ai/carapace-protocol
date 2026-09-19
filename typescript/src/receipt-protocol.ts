import canonicalize from 'canonicalize';

export const DOMAIN = 'carapace.tool-receipt.v2';
export const FIELDS = [
  'receipt_version', 'domain', 'receipt_id', 'issued_at', 'tool_id',
  'tool_version', 'agent_id', 'authorization_id', 'args_hash', 'result_hash',
  'status', 'public_key',
] as const;

function jsonValue(value: unknown): void {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    // Reject isolated UTF-16 surrogates; UTF-8 replacement would change the data.
    for (const character of value) {
      const point = character.codePointAt(0)!;
      if (point >= 0xd800 && point <= 0xdfff) throw new Error('Invalid Unicode');
    }
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new Error('Receipt JSON numbers must be finite and integers must be safe');
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) jsonValue(item);
    return;
  }
  if (typeof value === 'object' && value !== null &&
      (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    for (const [key, item] of Object.entries(value)) { jsonValue(key); jsonValue(item); }
    return;
  }
  throw new Error('Receipt content must be JSON');
}

export async function contentHash(value: unknown): Promise<string> {
  jsonValue(value);
  const text = canonicalize(value);
  if (text === undefined) throw new Error('Invalid JSON');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}

export function timestampMillis(value: unknown): number {
  if (typeof value !== 'string') throw new Error('Invalid timestamp');
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) throw new Error('Timestamp requires timezone');
  const [, year, month, day, hour, minute, second] = match.map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  const result = Date.parse(value);
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1] ||
      hour > 23 || minute > 59 || second > 59 || !Number.isFinite(result)) throw new Error('Invalid timestamp');
  return result;
}

export function receiptPayload(receipt: Record<string, unknown>): Record<string, unknown> {
  const expected = [...FIELDS, 'call_hash', 'signature'];
  if (Object.keys(receipt).length !== expected.length || expected.some(k => !(k in receipt))) {
    throw new Error('Incomplete or unknown receipt fields');
  }
  if (receipt.receipt_version !== '2' || receipt.domain !== DOMAIN) throw new Error('Unsupported receipt');
  for (const field of ['receipt_id', 'issued_at', 'tool_id']) {
    const value = receipt[field];
    if (typeof value !== 'string' || !value || Array.from(value).length > 512) throw new Error(`Invalid ${field}`);
  }
  for (const field of ['agent_id', 'tool_version', 'authorization_id']) {
    const value = receipt[field];
    if (value !== null && (typeof value !== 'string' || !value || Array.from(value).length > 512)) throw new Error(`Invalid ${field}`);
  }
  timestampMillis(receipt.issued_at);
  if (receipt.status !== 'ok' && receipt.status !== 'error') throw new Error('Invalid status');
  for (const field of ['args_hash', 'call_hash', 'result_hash', 'public_key']) {
    const value = receipt[field];
    if (value === null && (field === 'result_hash' || field === 'public_key')) continue;
    if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`Invalid ${field}`);
  }
  if (receipt.signature !== null && (typeof receipt.signature !== 'string' || !/^[0-9a-f]{128}$/.test(receipt.signature))) throw new Error('Invalid signature');
  if ((receipt.signature === null) !== (receipt.public_key === null)) throw new Error('Incomplete signature');
  return Object.fromEntries(FIELDS.map(field => [field, receipt[field]]));
}
