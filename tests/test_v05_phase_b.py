"""
Carapace SDK v0.5.0 Phase B Tests — Catalog Sync and Signed Receipts
"""
import hashlib
import json
import pytest
from unittest.mock import MagicMock, patch


# ─── Catalog tests ────────────────────────────────────────────────────────────

from carapace.catalog import (
    CatalogEntry,
    CatalogState,
    GateResult,
    fetch_catalog,
    run_gate_check,
)


def _make_catalog(tools=None) -> CatalogState:
    if tools is None:
        tools = [
            CatalogEntry(
                id="brave-search",
                name="Brave Search",
                description="Web search",
                endpoint_url="https://brave.com/mcp",
                status="active",
                clawmark_score=85,
                gate_pass=True,
                tier="free",
                safety_class="safe",
                certification_tier="clawmark_grandfathered",
                streaming_supported=False,
            ),
            CatalogEntry(
                id="low-score-tool",
                name="Low Score",
                description="Low score tool",
                endpoint_url="https://example.com/mcp",
                status="active",
                clawmark_score=50,
                gate_pass=False,
                tier="free",
                safety_class="safe",
                certification_tier="unclassified",
                streaming_supported=False,
            ),
            CatalogEntry(
                id="suspended-tool",
                name="Suspended",
                description="Suspended tool",
                endpoint_url="https://example.com/mcp",
                status="suspended",
                clawmark_score=90,
                gate_pass=True,
                tier="free",
                safety_class="safe",
                certification_tier="clawmark_grandfathered",
                streaming_supported=False,
            ),
        ]
    return CatalogState(
        catalog=tools,
        total=len(tools),
        etag="abc123",
        fetched_at="2026-05-19T00:00:00+00:00",
    )


class TestCatalogEntry:
    def test_from_dict_round_trips(self):
        d = {
            "id": "tool-1",
            "name": "Tool One",
            "description": "A tool",
            "endpoint_url": "https://example.com",
            "status": "active",
            "clawmark_score": 75,
            "gate_pass": False,
            "tier": "free",
            "safety_class": "safe",
            "certification_tier": "clawmark_grandfathered",
            "streaming_supported": True,
            "clawmark_breakdown": {"usage": 5},
            "scope_requirements": {},
        }
        entry = CatalogEntry.from_dict(d)
        assert entry.id == "tool-1"
        assert entry.clawmark_score == 75
        assert entry.streaming_supported is True

    def test_from_dict_handles_missing_optional_fields(self):
        d = {
            "id": "tool-2",
            "name": "Tool Two",
            "description": "",
            "endpoint_url": "https://example.com",
            "status": "active",
            "clawmark_score": 0,
            "gate_pass": False,
            "tier": "free",
            "safety_class": "safe",
            "certification_tier": "",
            "streaming_supported": False,
        }
        entry = CatalogEntry.from_dict(d)
        assert entry.clawmark_breakdown == {}
        assert entry.scope_requirements == {}


class TestCatalogState:
    def test_get_returns_entry(self):
        state = _make_catalog()
        entry = state.get("brave-search")
        assert entry is not None
        assert entry.name == "Brave Search"

    def test_get_returns_none_for_unknown(self):
        state = _make_catalog()
        assert state.get("nonexistent") is None

    def test_is_known(self):
        state = _make_catalog()
        assert state.is_known("brave-search") is True
        assert state.is_known("ghost") is False

    def test_is_active(self):
        state = _make_catalog()
        assert state.is_active("brave-search") is True
        assert state.is_active("suspended-tool") is False
        assert state.is_active("ghost") is False

    def test_gate_pass(self):
        state = _make_catalog()
        assert state.gate_pass("brave-search") is True
        assert state.gate_pass("low-score-tool") is False

    def test_active_tools(self):
        state = _make_catalog()
        actives = state.active_tools()
        assert all(e.status == "active" for e in actives)
        ids = {e.id for e in actives}
        assert "brave-search" in ids
        assert "suspended-tool" not in ids


class TestGateCheck:
    def test_all_gates_pass_for_good_tool(self):
        state = _make_catalog()
        result = run_gate_check("brave-search", state)
        assert result.passed is True
        assert result.gates_failed == []
        assert "catalog_membership" in result.gates_checked
        assert "active_status" in result.gates_checked
        assert "clawmark_gate" in result.gates_checked

    def test_fails_catalog_membership_for_unknown_tool(self):
        state = _make_catalog()
        result = run_gate_check("ghost-tool", state)
        assert result.passed is False
        assert result.blocked_by == "catalog_membership"

    def test_fails_active_status_for_suspended_tool(self):
        state = _make_catalog()
        result = run_gate_check("suspended-tool", state)
        assert result.passed is False
        assert result.blocked_by == "active_status"

    def test_fails_clawmark_gate_for_low_score(self):
        state = _make_catalog()
        result = run_gate_check("low-score-tool", state)
        assert result.passed is False
        assert result.blocked_by == "clawmark_gate"

    def test_fails_revocation_clear_when_in_revoked_set(self):
        state = _make_catalog()
        result = run_gate_check("brave-search", state, revoked_ids={"brave-search"})
        assert result.passed is False
        assert result.blocked_by == "revocation_clear"

    def test_custom_score_threshold(self):
        state = _make_catalog()
        # low-score-tool has score=50; threshold=40 should pass
        result = run_gate_check("low-score-tool", state, score_threshold=40)
        assert result.passed is True

    def test_delegation_gate_checked_when_provided(self):
        state = _make_catalog()
        result = run_gate_check("brave-search", state, delegation_valid=False)
        assert result.passed is False
        assert result.blocked_by == "delegation_valid"

    def test_delegation_gate_passes_when_valid(self):
        state = _make_catalog()
        result = run_gate_check("brave-search", state, delegation_valid=True)
        assert result.passed is True
        assert "delegation_valid" in result.gates_checked

    def test_observe_only_mode_passes_all(self):
        state = _make_catalog()
        result = run_gate_check("ghost-tool", state, trust_gates_enabled=False)
        assert result.passed is True
        assert result.details.get("mode") == "observe_only"

    def test_fail_open_when_catalog_is_none(self):
        result = run_gate_check("brave-search", None)
        assert result.passed is True
        assert result.details.get("mode") == "fail_open"
        assert result.details.get("reason") == "aria_unreachable"


class TestFetchCatalog:
    def test_304_returns_none_state(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 304
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_resp):
            state, new_etag = fetch_catalog("https://aria.example.com", etag="abc")
            assert state is None
            assert new_etag == "abc"

    def test_200_returns_catalog_state(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.headers = {"etag": '"xyz789"'}
        mock_resp.json.return_value = {
            "catalog": [
                {
                    "id": "tool-1",
                    "name": "Tool One",
                    "description": "",
                    "endpoint_url": "https://example.com",
                    "status": "active",
                    "clawmark_score": 80,
                    "gate_pass": True,
                    "tier": "free",
                    "safety_class": "safe",
                    "certification_tier": "",
                    "streaming_supported": False,
                }
            ],
            "total": 1,
            "etag": "xyz789",
        }

        with patch("httpx.get", return_value=mock_resp):
            state, new_etag = fetch_catalog("https://aria.example.com")
            assert state is not None
            assert state.total == 1
            assert state.catalog[0].id == "tool-1"
            assert new_etag == "xyz789"


# ─── Receipt tests ────────────────────────────────────────────────────────────

from carapace.receipt import create_receipt, verify_receipt, post_receipt


class TestCreateReceipt:
    def test_creates_receipt_with_expected_fields(self):
        receipt = create_receipt("brave-search", {"q": "test"}, {"results": []})
        assert receipt["tool_id"] == "brave-search"
        assert receipt["args_hash"] is not None
        assert receipt["result_hash"] is not None
        assert receipt["call_hash"] is not None
        assert receipt["status"] == "ok"
        assert receipt["signature"] is None
        assert receipt["public_key"] is None

    def test_call_hash_is_sha256_hex(self):
        receipt = create_receipt("tool-x", {"k": "v"})
        assert len(receipt["call_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in receipt["call_hash"])

    def test_different_args_produce_different_hashes(self):
        r1 = create_receipt("tool", {"q": "hello"})
        r2 = create_receipt("tool", {"q": "world"})
        assert r1["args_hash"] != r2["args_hash"]
        assert r1["call_hash"] != r2["call_hash"]

    def test_result_none_gives_none_result_hash(self):
        receipt = create_receipt("tool", {"q": "test"}, None)
        assert receipt["result_hash"] is None

    def test_result_present_gives_result_hash(self):
        receipt = create_receipt("tool", {"q": "test"}, {"answer": 42})
        assert receipt["result_hash"] is not None
        assert len(receipt["result_hash"]) == 64

    def test_agent_id_propagated(self):
        receipt = create_receipt("tool", {}, agent_id="agent-abc")
        assert receipt["agent_id"] == "agent-abc"

    def test_error_status(self):
        receipt = create_receipt("tool", {}, status="error")
        assert receipt["status"] == "error"

    def test_signed_receipt_has_signature_and_public_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes_raw()

        receipt = create_receipt("tool", {"q": "signed"}, private_key_bytes=priv_bytes)
        assert receipt["signature"] is not None
        assert receipt["public_key"] is not None
        assert len(receipt["signature"]) == 128  # 64 bytes → 128 hex chars
        assert len(receipt["public_key"]) == 64  # 32 bytes → 64 hex chars


class TestVerifyReceipt:
    def _make_signed_receipt(self) -> tuple[dict, str]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes_raw()
        pub_hex = priv.public_key().public_bytes_raw().hex()
        receipt = create_receipt("tool", {"q": "test"}, private_key_bytes=priv_bytes)
        return receipt, pub_hex

    def test_valid_signature_verifies(self):
        receipt, pub_hex = self._make_signed_receipt()
        assert verify_receipt(receipt, pub_hex) is True

    def test_verify_uses_embedded_public_key(self):
        receipt, _ = self._make_signed_receipt()
        # public_key is embedded in receipt
        assert verify_receipt(receipt) is True

    def test_tampered_call_hash_fails_verification(self):
        receipt, pub_hex = self._make_signed_receipt()
        receipt["call_hash"] = "0" * 64
        assert verify_receipt(receipt, pub_hex) is False

    def test_wrong_public_key_fails(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        receipt, _ = self._make_signed_receipt()
        other_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        assert verify_receipt(receipt, other_pub) is False

    def test_unsigned_receipt_returns_false(self):
        receipt = create_receipt("tool", {})
        assert verify_receipt(receipt) is False

    def test_missing_call_hash_returns_false(self):
        receipt = {"signature": "abc", "public_key": "def", "call_hash": ""}
        assert verify_receipt(receipt) is False


class TestPostReceipt:
    def test_returns_true_on_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True

        with patch("httpx.post", return_value=mock_resp):
            result = post_receipt(
                "https://aria.example.com",
                {"tool_id": "tool", "call_hash": "abc", "status": "ok"},
            )
            assert result is True

    def test_returns_false_on_network_error(self):
        with patch("httpx.post", side_effect=Exception("connection refused")):
            result = post_receipt(
                "https://aria.example.com",
                {"tool_id": "tool", "call_hash": "abc", "status": "ok"},
            )
            assert result is False

    def test_returns_false_on_server_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.post", return_value=mock_resp):
            result = post_receipt(
                "https://aria.example.com",
                {"tool_id": "tool", "call_hash": "abc", "status": "ok"},
            )
            assert result is False


# ─── SDK top-level import check ───────────────────────────────────────────────

class TestSDKExports:
    def test_version_is_v050(self):
        import carapace
        assert carapace.__version__ == "0.5.0"

    def test_catalog_types_importable_from_top_level(self):
        from carapace import CatalogEntry, CatalogState, GateResult, fetch_catalog, run_gate_check
        assert CatalogEntry is not None
        assert CatalogState is not None
        assert GateResult is not None
        assert callable(fetch_catalog)
        assert callable(run_gate_check)

    def test_receipt_functions_importable_from_top_level(self):
        from carapace import create_receipt, verify_receipt, post_receipt, post_receipt_async
        assert callable(create_receipt)
        assert callable(verify_receipt)
        assert callable(post_receipt)
        assert callable(post_receipt_async)
