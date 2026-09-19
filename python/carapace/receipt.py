"""Versioned tool-call receipts. Content hashes minimize data; they are not anonymity.

v2 signs a hash of the complete canonical envelope. Legacy receipts remain readable
but verify_receipt deliberately returns False: their action metadata is unbound.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from .receipt_protocol import DOMAIN, FIELDS, content_hash, validate_receipt


def create_receipt(
    tool_id: str, args: Any, result: Any = None, *,
    agent_id: Optional[str] = None, status: str = "ok",
    private_key_bytes: Optional[bytes] = None,
    tool_version: Optional[str] = None, authorization_id: Optional[str] = None,
) -> dict[str, Any]:
    """Create v2; persist and retry this same object for idempotent ingestion.

    JSON-only args/results use RFC 8785; non-finite/unsafe integer values fail.
    An embedded signing key establishes integrity, not trusted agent identity.
    ARIA binds signed v2 receipts to the agent's current registered key.
    """
    receipt = {
        "receipt_version": "2", "domain": DOMAIN,
        "receipt_id": str(uuid4()), "issued_at": datetime.now(timezone.utc).isoformat(),
        "tool_id": tool_id, "tool_version": tool_version,
        "agent_id": agent_id, "authorization_id": authorization_id,
        "args_hash": content_hash(args),
        "result_hash": content_hash(result) if result is not None else None,
        "status": status, "public_key": None, "signature": None,
    }
    private_key = None
    if private_key_bytes is not None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        receipt["public_key"] = private_key.public_key().public_bytes_raw().hex()
    receipt["call_hash"] = content_hash({field: receipt[field] for field in FIELDS})
    if private_key is not None:
        receipt["signature"] = private_key.sign(receipt["call_hash"].encode("ascii")).hex()
    if not validate_receipt(receipt):
        raise ValueError("Invalid receipt fields (status must be ok or error)")
    return receipt


def verify_receipt(receipt: dict[str, Any], public_key_hex: Optional[str] = None) -> bool:
    """Verify signed v2 envelope integrity. Legacy/unsigned/malformed return False.

    Pin a trusted key to authenticate the signer. Without it, this only verifies
    possession of the embedded key; it does not prove an action occurred.
    """
    return bool(isinstance(receipt, dict) and receipt.get("signature")
                and validate_receipt(receipt, public_key_hex))


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
            if not 200 <= resp.status_code < 300:
                return False
            if receipt.get("receipt_version") != "2":
                return True
            ack = resp.json()
            expected = "verified_v2" if receipt.get("signature") else "unsigned_v2"
            return ack.get("ok") is True and ack.get("verification_status") == expected
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
        if not 200 <= resp.status_code < 300:
            return False
        if receipt.get("receipt_version") != "2":
            return True
        ack = resp.json()
        expected = "verified_v2" if receipt.get("signature") else "unsigned_v2"
        return ack.get("ok") is True and ack.get("verification_status") == expected
    except Exception:
        return False
