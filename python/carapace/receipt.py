"""
Carapace SDK v0.5.0 — Signed Tool-Call Receipts

Receipts provide a cryptographic audit trail for tool calls. They store
content hashes only — no PII or raw call content is ever written.

Posting receipts to ARIA is best-effort (never raises). A failure to
post MUST NOT block the tool call.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional


def _sha256_json(obj: Any) -> str:
    """SHA-256 of deterministic JSON serialization."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def create_receipt(
    tool_id: str,
    args: Any,
    result: Any = None,
    *,
    agent_id: Optional[str] = None,
    status: str = "ok",
    private_key_bytes: Optional[bytes] = None,
) -> dict[str, Any]:
    """
    Create a signed tool-call receipt.

    Stores SHA-256 hashes of args and result — no raw content.
    Signs the call_hash with the agent's Ed25519 private key when provided.

    The returned dict is ready to POST to /aria/v1/receipts.

    Args:
        tool_id: The ARIA tool ID (e.g. "brave-search")
        args: The tool call arguments (any JSON-serializable value)
        result: The tool call result (any JSON-serializable value), or None
        agent_id: The calling agent's ARIA ID
        status: "ok" | "error"
        private_key_bytes: 32-byte Ed25519 private key. When provided,
                           the receipt is signed. When None, unsigned but valid.

    Returns:
        dict ready for POST /aria/v1/receipts
    """
    if status not in ("ok", "error"):
        raise ValueError(f"status must be 'ok' or 'error', got {status!r}")

    args_hash = _sha256_json(args)
    result_hash = _sha256_json(result) if result is not None else None
    ts = datetime.now(timezone.utc).isoformat()

    call_hash = hashlib.sha256(
        f"{tool_id}:{args_hash}:{result_hash or ''}:{ts}".encode()
    ).hexdigest()

    signature: Optional[str] = None
    public_key_hex: Optional[str] = None

    if private_key_bytes is not None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            priv = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            raw_sig = priv.sign(call_hash.encode())
            signature = raw_sig.hex()
            public_key_hex = priv.public_key().public_bytes_raw().hex()
        except Exception as exc:
            raise ValueError(f"Failed to sign receipt: {exc}") from exc

    return {
        "tool_id": tool_id,
        "agent_id": agent_id,
        "call_hash": call_hash,
        "args_hash": args_hash,
        "result_hash": result_hash,
        "signature": signature,
        "public_key": public_key_hex,
        "status": status,
    }


def verify_receipt(receipt: dict[str, Any], public_key_hex: Optional[str] = None) -> bool:
    """
    Verify a receipt's Ed25519 signature.

    Uses the public_key from the receipt itself when public_key_hex is None.
    Returns False (not raises) on any verification failure.
    """
    sig = receipt.get("signature")
    pk = public_key_hex or receipt.get("public_key")
    call_hash = receipt.get("call_hash")

    if not sig or not pk or not call_hash:
        return False

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk))
        pub.verify(bytes.fromhex(sig), call_hash.encode())
        return True
    except Exception:
        return False


async def post_receipt_async(
    aria_url: str,
    receipt: dict[str, Any],
    *,
    api_key: Optional[str] = None,
    timeout: float = 3.0,
) -> bool:
    """
    Best-effort async receipt post. Returns True on success, False on any failure.
    NEVER raises — a failed post MUST NOT block the tool call.
    """
    try:
        import httpx

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{aria_url.rstrip('/')}/aria/v1/receipts",
                json=receipt,
                headers=headers,
                timeout=timeout,
            )
            return resp.status_code < 400
    except Exception:
        return False


def post_receipt(
    aria_url: str,
    receipt: dict[str, Any],
    *,
    api_key: Optional[str] = None,
    timeout: float = 3.0,
) -> bool:
    """
    Best-effort sync receipt post. Returns True on success, False on any failure.
    NEVER raises — a failed post MUST NOT block the tool call.
    """
    try:
        import httpx

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        resp = httpx.post(
            f"{aria_url.rstrip('/')}/aria/v1/receipts",
            json=receipt,
            headers=headers,
            timeout=timeout,
        )
        return resp.status_code < 400
    except Exception:
        return False
