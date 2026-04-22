"""
Carapace Protocol — Signed Revocation List Endpoint
====================================================
Drop into your existing ARIA FastAPI app.

Endpoint: GET /aria/v1/revocations
Returns:  A signed, timestamped revocation list (CRL) in JSON format.

The list is signed with the ARIA server's Ed25519 key so that offline
verifiers can confirm it came from an authoritative source and has not
been tampered with.

Usage in offline verification:
    from carapace.revocation import RevocationCache
    cache = RevocationCache(registry_url="https://api.relayforge.tools/aria/v1")
    cache.refresh()  # pull latest CRL
    is_revoked = cache.is_revoked(agent_id)
"""

import os
import json
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
import base64

from .database import get_db, AgentRecord  # your existing DB layer
from .auth import require_admin             # your existing auth


# ─── Schema ───────────────────────────────────────────────────────────────────

class RevokedEntry(BaseModel):
    agent_id: str
    revoked_at: str          # ISO 8601
    reason: Optional[str]    # optional human-readable reason
    revoked_by: str          # "owner" | "registry" | "evaluator"


class RevocationList(BaseModel):
    """
    Signed Carapace Revocation List (CRL).

    The `entries` array contains all currently revoked agent IDs.
    The `signature` covers the canonical JSON of the list body
    (everything except the signature field itself) using JCS ordering.

    Verifiers should:
      1. Strip the `signature` field
      2. Canonicalize remaining fields (sorted keys, no whitespace)
      3. Verify signature against the ARIA server public key
      4. Check `valid_until` — reject stale lists
    """
    version: str = "1"
    issued_at: str           # ISO 8601
    valid_until: str         # ISO 8601 — list expires after this
    issuer: str              # ARIA registry URL
    issuer_public_key: str   # hex Ed25519 public key
    entry_count: int
    entries: list[RevokedEntry]
    list_hash: str           # SHA-256 of canonical entries JSON (integrity check)
    signature: str           # Ed25519 hex over canonical list body (excl. signature)


class RevocationCheckResponse(BaseModel):
    agent_id: str
    revoked: bool
    revoked_at: Optional[str]
    reason: Optional[str]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_signing_key() -> SigningKey:
    """Load ARIA server signing key from environment."""
    raw = os.environ.get("ARIA_SERVER_SIGNING_KEY")
    if not raw:
        raise RuntimeError("ARIA_SERVER_SIGNING_KEY not set")
    return SigningKey(bytes.fromhex(raw))


def _canonical_json(obj: dict) -> bytes:
    """
    JCS-style canonicalization: sorted keys, no whitespace.
    Used as the signing payload — matches carapace-sdk behaviour.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _build_revocation_list(entries: list[RevokedEntry],
                            issuer_url: str,
                            signing_key: SigningKey,
                            ttl_minutes: int = 60) -> RevocationList:
    """
    Build and sign a RevocationList from a list of RevokedEntry objects.
    TTL controls how long downstream caches should consider the list valid.
    """
    now = datetime.now(timezone.utc)
    valid_until = now + timedelta(minutes=ttl_minutes)

    # Canonical entries for hashing
    entries_payload = [e.model_dump() for e in entries]
    entries_canonical = _canonical_json(entries_payload)
    list_hash = hashlib.sha256(entries_canonical).hexdigest()

    # Build signable body (everything except the signature field)
    body = {
        "version": "1",
        "issued_at": now.isoformat(),
        "valid_until": valid_until.isoformat(),
        "issuer": issuer_url,
        "issuer_public_key": signing_key.verify_key.encode(HexEncoder).decode(),
        "entry_count": len(entries),
        "entries": entries_payload,
        "list_hash": list_hash,
    }
    canonical_body = _canonical_json(body)

    # Sign
    signed = signing_key.sign(canonical_body, encoder=HexEncoder)
    signature_hex = signed.signature.decode()

    return RevocationList(
        **body,
        signature=signature_hex,
    )


# ─── Router ───────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/aria/v1", tags=["revocations"])

ISSUER_URL = os.environ.get(
    "ARIA_ISSUER_URL", "https://api.relayforge.tools/aria/v1"
)

# Simple in-process cache to avoid signing on every request.
# Replace with Redis or similar for multi-instance deployments.
_crl_cache: Optional[RevocationList] = None
_crl_cache_until: float = 0.0
CRL_CACHE_SECONDS = 60  # regenerate at most once per minute


@router.get(
    "/revocations",
    response_model=RevocationList,
    summary="Get signed revocation list",
    description=(
        "Returns a signed, timestamped list of all revoked agent IDs. "
        "The list is valid for the duration specified in `valid_until`. "
        "Offline verifiers should pull this list periodically and cache it. "
        "Signature is Ed25519 over JCS-canonical list body."
    ),
)
async def get_revocation_list(db=Depends(get_db)) -> RevocationList:
    global _crl_cache, _crl_cache_until

    now = time.monotonic()
    if _crl_cache and now < _crl_cache_until:
        return _crl_cache

    # Fetch all revoked agents from DB
    revoked_records: list[AgentRecord] = db.query(AgentRecord).filter(
        AgentRecord.status == "revoked"
    ).all()

    entries = [
        RevokedEntry(
            agent_id=r.id,
            revoked_at=r.revoked_at.isoformat() if r.revoked_at else r.updated_at.isoformat(),
            reason=r.revocation_reason,
            revoked_by=r.revoked_by or "registry",
        )
        for r in revoked_records
    ]

    signing_key = _get_signing_key()
    crl = _build_revocation_list(entries, ISSUER_URL, signing_key)

    _crl_cache = crl
    _crl_cache_until = now + CRL_CACHE_SECONDS

    return crl


@router.get(
    "/revocations/{agent_id}",
    response_model=RevocationCheckResponse,
    summary="Check single agent revocation status",
    description=(
        "Lightweight check for a single agent ID. "
        "Returns revocation status without returning the full list. "
        "For bulk/offline use, prefer GET /revocations."
    ),
)
async def check_revocation(agent_id: str, db=Depends(get_db)) -> RevocationCheckResponse:
    record: Optional[AgentRecord] = db.query(AgentRecord).filter(
        AgentRecord.id == agent_id
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Agent not found")

    if record.status != "revoked":
        return RevocationCheckResponse(
            agent_id=agent_id,
            revoked=False,
            revoked_at=None,
            reason=None,
        )

    return RevocationCheckResponse(
        agent_id=agent_id,
        revoked=True,
        revoked_at=record.revoked_at.isoformat() if record.revoked_at else None,
        reason=record.revocation_reason,
    )


# ─── SDK-side: RevocationCache ────────────────────────────────────────────────
"""
Add this to carapace-sdk (Python). Handles pulling, verifying,
and caching the signed CRL for offline use.

Usage:
    from carapace.revocation import RevocationCache

    cache = RevocationCache(
        registry_url="https://api.relayforge.tools/aria/v1",
        issuer_public_key="<hex>",   # pin the ARIA server key
        ttl_seconds=300,             # how long to cache before refresh
    )
    cache.refresh()
    assert not cache.is_revoked("some-agent-uuid")
"""

REVOCATION_CACHE_CODE = '''
import time
import json
import hashlib
import requests
from typing import Optional
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError


class RevocationCacheError(Exception):
    pass


class RevocationCache:
    """
    Client-side signed revocation list cache.

    Pulls the CRL from ARIA, verifies the signature against the
    pinned issuer public key, and caches revoked agent IDs for
    fast offline lookup.
    """

    def __init__(
        self,
        registry_url: str,
        issuer_public_key: Optional[str] = None,
        ttl_seconds: int = 300,
    ):
        self.url = registry_url.rstrip("/") + "/revocations"
        self.issuer_public_key = issuer_public_key
        self.ttl_seconds = ttl_seconds
        self._revoked: set[str] = set()
        self._valid_until: float = 0.0
        self._last_refresh: float = 0.0

    def refresh(self) -> None:
        """Pull and verify the latest CRL from ARIA."""
        resp = requests.get(self.url, timeout=10)
        resp.raise_for_status()
        crl = resp.json()

        self._verify_crl(crl)

        self._revoked = {e["agent_id"] for e in crl.get("entries", [])}
        self._last_refresh = time.monotonic()
        # honour the server\'s valid_until if shorter than our TTL
        from datetime import datetime, timezone
        server_until = datetime.fromisoformat(crl["valid_until"]).timestamp()
        local_until = time.time() + self.ttl_seconds
        self._valid_until = min(server_until, local_until)

    def _verify_crl(self, crl: dict) -> None:
        """Verify Ed25519 signature on the CRL body."""
        sig_hex = crl.pop("signature", None)
        if not sig_hex:
            raise RevocationCacheError("CRL missing signature")

        # Determine which key to verify against
        key_hex = self.issuer_public_key or crl.get("issuer_public_key")
        if not key_hex:
            raise RevocationCacheError("No issuer public key available")

        # Verify entries hash
        entries_canonical = json.dumps(
            crl.get("entries", []), sort_keys=True,
            separators=(",", ":"), ensure_ascii=False
        ).encode()
        expected_hash = hashlib.sha256(entries_canonical).hexdigest()
        if crl.get("list_hash") != expected_hash:
            raise RevocationCacheError("CRL entries hash mismatch")

        # Verify signature over canonical body (sig already removed)
        canonical = json.dumps(
            crl, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()

        try:
            vk = VerifyKey(bytes.fromhex(key_hex))
            vk.verify(canonical, bytes.fromhex(sig_hex))
        except BadSignatureError:
            raise RevocationCacheError("CRL signature verification failed")
        finally:
            crl["signature"] = sig_hex  # restore

    def is_revoked(self, agent_id: str) -> bool:
        """
        Check if an agent is revoked.
        Auto-refreshes if the cache has expired.
        """
        if time.time() > self._valid_until:
            self.refresh()
        return agent_id in self._revoked

    def is_stale(self) -> bool:
        """True if the cache needs a refresh."""
        return time.time() > self._valid_until

    @property
    def revoked_count(self) -> int:
        return len(self._revoked)
'''

# Write SDK file alongside this module for Sheldon to drop in
if __name__ == "__main__":
    with open("revocation_cache.py", "w") as f:
        f.write(REVOCATION_CACHE_CODE.strip())
    print("Wrote revocation_cache.py")
