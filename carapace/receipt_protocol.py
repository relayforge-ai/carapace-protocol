"""Receipt v2 wire contract. Mirrored in ARIA; shared vectors guard parity."""
from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime
from typing import Any

import jcs

DOMAIN = "carapace.tool-receipt.v2"
FIELDS = (
    "receipt_version", "domain", "receipt_id", "issued_at", "tool_id",
    "tool_version", "agent_id", "authorization_id", "args_hash", "result_hash",
    "status", "public_key",
)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")


def _json_value(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return
    if isinstance(value, (int, float)):
        if not math.isfinite(value) or (value == int(value) and abs(value) > 2**53 - 1):
            raise ValueError("Receipt JSON numbers must be finite and integers must be safe")
        return
    if isinstance(value, list):
        for item in value:
            _json_value(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _json_value(key)
            _json_value(item)
        return
    raise ValueError("Receipt content must be JSON; implicit string conversion is forbidden")


def canonical_bytes(value: Any) -> bytes:
    _json_value(value)
    return jcs.canonicalize(value)


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def receipt_payload(receipt: dict) -> dict:
    if set(receipt) != set(FIELDS) | {"call_hash", "signature"}:
        raise ValueError("Incomplete or unknown receipt fields")
    if receipt["receipt_version"] != "2" or receipt["domain"] != DOMAIN:
        raise ValueError("Unsupported receipt version/domain")
    for field in ("receipt_id", "issued_at", "tool_id"):
        if not isinstance(receipt[field], str) or not receipt[field] or len(receipt[field]) > 512:
            raise ValueError(f"Invalid {field}")
    for field in ("agent_id", "tool_version", "authorization_id"):
        value = receipt[field]
        if value is not None and (not isinstance(value, str) or not value or len(value) > 512):
            raise ValueError(f"Invalid {field}")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", receipt["issued_at"]):
        raise ValueError("Receipt time must be an ISO timestamp with timezone")
    issued = datetime.fromisoformat(receipt["issued_at"].replace("Z", "+00:00"))
    if issued.tzinfo is None:
        raise ValueError("Receipt time must include timezone")
    if receipt["status"] not in ("ok", "error"):
        raise ValueError("Invalid receipt status")
    for field in ("args_hash", "call_hash"):
        if not isinstance(receipt[field], str) or not HEX64.fullmatch(receipt[field]):
            raise ValueError(f"Invalid {field}")
    for field in ("result_hash", "public_key"):
        if receipt[field] is not None and (not isinstance(receipt[field], str) or not HEX64.fullmatch(receipt[field])):
            raise ValueError(f"Invalid {field}")
    sig = receipt["signature"]
    if sig is not None and (not isinstance(sig, str) or not HEX128.fullmatch(sig)):
        raise ValueError("Invalid signature")
    if (sig is None) != (receipt["public_key"] is None):
        raise ValueError("Signature and public key must occur together")
    return {field: receipt[field] for field in FIELDS}


def validate_receipt(receipt: dict, public_key_hex: str | None = None) -> bool:
    """Validate v2 integrity. True for unsigned v2; this is NOT issuer trust."""
    try:
        payload = receipt_payload(receipt)
        if content_hash(payload) != receipt["call_hash"]:
            return False
        if public_key_hex is not None and public_key_hex != receipt["public_key"]:
            return False
        if receipt["signature"] is not None:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(receipt["public_key"]))
            key.verify(bytes.fromhex(receipt["signature"]), receipt["call_hash"].encode("ascii"))
        return True
    except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
        return False
    except Exception:
        # Cryptography's InvalidSignature is deliberately returned as a negative result.
        return False
