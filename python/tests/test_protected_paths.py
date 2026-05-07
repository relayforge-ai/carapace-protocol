"""
Tests for Carapace v0.3 Protected Path Guard.

Coverage:
- is_protected_path: protected and non-protected paths, globs, subdirectories
- check_protected_write: blocked by default, approval source validation,
  expiry, scope mismatch, valid approval, audit log entries
- Scenario tests: identity rewrite, config rewrite, env write,
  normal workspace write, authorized protected write
- AuditLogEntry serialisation
- ProtectedWriteApproval validation (gate_word, source, expiry, scope)
- Thread-safety smoke test for the in-memory audit log

Run: pytest tests/test_protected_paths.py -v
"""

from __future__ import annotations

import threading
import pytest
from datetime import datetime, timedelta, timezone

from carapace.expiry import make_expires_at
from carapace.protected_paths import (
    UNAUTHORIZED_SOURCES,
    ApprovalSourceForbidden,
    AuditLogEntry,
    ProtectedWriteApproval,
    ProtectedWriteBlocked,
    check_protected_write,
    clear_audit_log,
    get_audit_log,
    is_protected_path,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def future(hours: float = 1) -> str:
    dt = datetime.now(timezone.utc) + timedelta(hours=hours)
    return dt.isoformat().replace("+00:00", "Z")


def past(hours: float = 1) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return dt.isoformat().replace("+00:00", "Z")


def make_approval(
    gate_word: str = "SHELDON-ALPHA",
    path_scope: str = "IDENTITY.md",
    issued_by: str = "human",
    expires_at: str | None = None,
) -> ProtectedWriteApproval:
    return ProtectedWriteApproval(
        gate_word=gate_word,
        path_scope=path_scope,
        issued_by=issued_by,
        expires_at=expires_at or future(1),
    )


# ── Setup ─────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_audit_log():
    """Ensure a clean audit log for each test."""
    clear_audit_log()
    yield
    clear_audit_log()


# ═══════════════════════════════════════════════════════════════════════════════
# is_protected_path
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsProtectedPath:
    # Identity files
    def test_identity_md_is_protected(self):
        assert is_protected_path("IDENTITY.md") is True

    def test_system_md_is_protected(self):
        assert is_protected_path("SYSTEM.md") is True

    def test_agent_md_is_protected(self):
        assert is_protected_path("AGENT.md") is True

    # Runtime config
    def test_openclaw_json_is_protected(self):
        assert is_protected_path("openclaw.json") is True

    # Environment files
    def test_env_is_protected(self):
        assert is_protected_path(".env") is True

    def test_env_local_is_protected(self):
        assert is_protected_path(".env.local") is True

    def test_env_production_is_protected(self):
        assert is_protected_path(".env.production") is True

    # Secrets directory
    def test_secrets_file_is_protected(self):
        assert is_protected_path("secrets/api_key.txt") is True

    def test_secrets_subdir_is_protected(self):
        assert is_protected_path("secrets/prod/db.json") is True

    # Config directory
    def test_config_file_is_protected(self):
        assert is_protected_path("config/settings.json") is True

    def test_config_nested_is_protected(self):
        assert is_protected_path("config/routing/main.yaml") is True

    # Policies directory
    def test_policies_file_is_protected(self):
        assert is_protected_path("policies/write_policy.json") is True

    # Runtime directory
    def test_runtime_file_is_protected(self):
        assert is_protected_path("runtime/state.json") is True

    # Model routing configs
    def test_model_routing_json_is_protected(self):
        assert is_protected_path("model_routing.json") is True

    def test_model_routing_yaml_is_protected(self):
        assert is_protected_path("model_routing.yaml") is True

    def test_model_routing_yml_is_protected(self):
        assert is_protected_path("model_routing.yml") is True

    # Tool permission configs
    def test_tool_permissions_json_is_protected(self):
        assert is_protected_path("tool_permissions.json") is True

    # Memory policy
    def test_memory_policy_json_is_protected(self):
        assert is_protected_path("memory_policy.json") is True

    # Non-protected paths
    def test_readme_is_not_protected(self):
        assert is_protected_path("README.md") is False

    def test_source_file_is_not_protected(self):
        assert is_protected_path("src/main.py") is False

    def test_workspace_data_is_not_protected(self):
        assert is_protected_path("workspace/notes.txt") is False

    def test_output_json_is_not_protected(self):
        assert is_protected_path("output.json") is False

    # Extra patterns
    def test_extra_pattern_is_honoured(self):
        assert is_protected_path("custom_gate.json", extra_patterns=["custom_gate.json"]) is True

    def test_extra_pattern_does_not_affect_others(self):
        assert is_protected_path("README.md", extra_patterns=["custom_gate.json"]) is False

    # Backslash normalisation (Windows paths)
    def test_windows_path_normalised(self):
        assert is_protected_path("config\\settings.json") is True

    def test_windows_secrets_normalised(self):
        assert is_protected_path("secrets\\api_key.txt") is True


# ═══════════════════════════════════════════════════════════════════════════════
# ProtectedWriteApproval validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestProtectedWriteApproval:
    def test_valid_approval_constructs(self):
        a = make_approval()
        assert a.gate_word == "SHELDON-ALPHA"
        assert a.issued_by == "human"
        assert not a.is_expired

    def test_empty_gate_word_rejected(self):
        with pytest.raises(ValueError, match="gate_word"):
            ProtectedWriteApproval(
                gate_word="   ",
                path_scope="IDENTITY.md",
                issued_by="human",
                expires_at=future(),
            )

    def test_empty_path_scope_rejected(self):
        with pytest.raises(ValueError, match="path_scope"):
            ProtectedWriteApproval(
                gate_word="ALPHA",
                path_scope="",
                issued_by="human",
                expires_at=future(),
            )

    def test_missing_expires_at_rejected(self):
        with pytest.raises(ValueError, match="expires_at"):
            ProtectedWriteApproval(
                gate_word="ALPHA",
                path_scope="IDENTITY.md",
                issued_by="human",
                expires_at="",
            )

    @pytest.mark.parametrize("source", list(UNAUTHORIZED_SOURCES))
    def test_unauthorized_source_rejected(self, source: str):
        with pytest.raises(ApprovalSourceForbidden):
            ProtectedWriteApproval(
                gate_word="ALPHA",
                path_scope="IDENTITY.md",
                issued_by=source,
                expires_at=future(),
            )

    def test_expired_approval_detected(self):
        a = ProtectedWriteApproval(
            gate_word="ALPHA",
            path_scope="IDENTITY.md",
            issued_by="human",
            expires_at=past(),
        )
        assert a.is_expired is True

    def test_future_approval_not_expired(self):
        a = make_approval()
        assert a.is_expired is False

    def test_covers_path_exact(self):
        a = make_approval(path_scope="IDENTITY.md")
        assert a.covers_path("IDENTITY.md") is True
        assert a.covers_path("SYSTEM.md") is False

    def test_covers_path_glob(self):
        a = make_approval(path_scope="config/*")
        assert a.covers_path("config/settings.json") is True
        assert a.covers_path("policies/rules.json") is False

    def test_covers_path_normalises_windows_path(self):
        a = make_approval(path_scope="config/*")
        assert a.covers_path("config\\settings.json") is True

    def test_token_id_auto_generated(self):
        a = make_approval()
        b = make_approval()
        assert a.token_id != b.token_id

    def test_custom_token_id_preserved(self):
        a = ProtectedWriteApproval(
            gate_word="X",
            path_scope="IDENTITY.md",
            issued_by="human",
            expires_at=future(),
            token_id="fixed-id-123",
        )
        assert a.token_id == "fixed-id-123"


# ═══════════════════════════════════════════════════════════════════════════════
# check_protected_write — core scenarios
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckProtectedWrite:
    # ── Scenario 1: identity rewrite (blocked) ────────────────────────────────

    def test_identity_rewrite_blocked_by_default(self):
        """Prompt-injection identity rewrite is refused without approval."""
        with pytest.raises(ProtectedWriteBlocked) as exc_info:
            check_protected_write("IDENTITY.md")
        assert exc_info.value.path == "IDENTITY.md"
        assert exc_info.value.reason == "no_approval_provided"
        assert exc_info.value.pattern_matched == "IDENTITY.md"

    def test_identity_rewrite_blocked_creates_audit_entry(self):
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write("IDENTITY.md")
        log = get_audit_log()
        assert len(log) == 1
        entry = log[0]
        assert entry.path == "IDENTITY.md"
        assert entry.outcome == "blocked"
        assert entry.reason == "no_approval_provided"

    # ── Scenario 2: config rewrite (blocked) ──────────────────────────────────

    def test_config_rewrite_blocked_by_default(self):
        """Agent cannot silently overwrite config files."""
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write("config/settings.json")

    def test_config_rewrite_audit_entry(self):
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write("config/settings.json", operation="edit")
        log = get_audit_log()
        assert log[0].operation == "edit"
        assert log[0].outcome == "blocked"

    # ── Scenario 3: env write (blocked) ───────────────────────────────────────

    def test_env_write_blocked(self):
        """Writing .env requires human approval."""
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write(".env")

    def test_env_local_write_blocked(self):
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write(".env.local")

    # ── Scenario 4: normal workspace write (allowed) ──────────────────────────

    def test_normal_workspace_write_allowed(self):
        """Non-protected workspace files are not blocked."""
        entry = check_protected_write("workspace/notes.txt")
        assert entry.outcome == "approved"
        assert entry.reason == "path_not_protected"

    def test_source_file_write_allowed(self):
        entry = check_protected_write("src/utils.py")
        assert entry.outcome == "approved"

    def test_readme_write_allowed(self):
        entry = check_protected_write("README.md")
        assert entry.outcome == "approved"

    # ── Scenario 5: authorized protected write (approved) ─────────────────────

    def test_authorized_identity_write_approved(self):
        """A valid human-issued approval permits the write."""
        approval = make_approval(path_scope="IDENTITY.md")
        entry = check_protected_write("IDENTITY.md", approval=approval)
        assert entry.outcome == "approved"
        assert entry.reason == "valid_approval"
        assert entry.pattern_matched == "IDENTITY.md"

    def test_authorized_write_gate_word_prefix_logged(self):
        """Only the first 4 chars of the gate word appear in the audit log."""
        approval = make_approval(gate_word="SHELDON-ALPHA", path_scope="IDENTITY.md")
        entry = check_protected_write("IDENTITY.md", approval=approval)
        assert entry.approval_gate_word_prefix == "SHEL"

    def test_authorized_write_token_id_logged(self):
        approval = make_approval(path_scope=".env")
        entry = check_protected_write(".env", approval=approval)
        assert entry.approval_token_id == approval.token_id

    def test_authorized_write_issued_by_logged(self):
        approval = make_approval(issued_by="human", path_scope="SYSTEM.md")
        entry = check_protected_write("SYSTEM.md", approval=approval)
        assert entry.issued_by == "human"

    def test_glob_scope_approval_covers_config_file(self):
        approval = make_approval(path_scope="config/*")
        entry = check_protected_write("config/routing.json", approval=approval)
        assert entry.outcome == "approved"

    def test_glob_scope_approval_covers_windows_config_file(self):
        approval = make_approval(path_scope="config/*")
        entry = check_protected_write("config\\routing.json", approval=approval)
        assert entry.outcome == "approved"

    # ── Approval failure modes ────────────────────────────────────────────────

    def test_expired_approval_blocked(self):
        approval = ProtectedWriteApproval(
            gate_word="ALPHA",
            path_scope="IDENTITY.md",
            issued_by="human",
            expires_at=past(),
        )
        with pytest.raises(ProtectedWriteBlocked) as exc:
            check_protected_write("IDENTITY.md", approval=approval)
        assert exc.value.reason == "approval_expired"

    def test_scope_mismatch_blocked(self):
        """An approval for .env does not cover IDENTITY.md."""
        approval = make_approval(path_scope=".env")
        with pytest.raises(ProtectedWriteBlocked) as exc:
            check_protected_write("IDENTITY.md", approval=approval)
        assert exc.value.reason == "approval_scope_mismatch"

    def test_approval_from_agent_source_blocked(self):
        """Agent-issued approvals must be rejected even before the write."""
        with pytest.raises(ApprovalSourceForbidden):
            ProtectedWriteApproval(
                gate_word="ALPHA",
                path_scope="IDENTITY.md",
                issued_by="agent",
                expires_at=future(),
            )

    def test_approval_from_tool_source_blocked(self):
        with pytest.raises(ApprovalSourceForbidden):
            ProtectedWriteApproval(
                gate_word="ALPHA",
                path_scope="IDENTITY.md",
                issued_by="tool",
                expires_at=future(),
            )

    def test_approval_from_file_source_blocked(self):
        with pytest.raises(ApprovalSourceForbidden):
            ProtectedWriteApproval(
                gate_word="ALPHA",
                path_scope="IDENTITY.md",
                issued_by="file",
                expires_at=future(),
            )

    def test_approval_from_browser_output_blocked(self):
        with pytest.raises(ApprovalSourceForbidden):
            ProtectedWriteApproval(
                gate_word="ALPHA",
                path_scope="IDENTITY.md",
                issued_by="browser_output",
                expires_at=future(),
            )

    def test_approval_from_subagent_blocked(self):
        with pytest.raises(ApprovalSourceForbidden):
            ProtectedWriteApproval(
                gate_word="ALPHA",
                path_scope="IDENTITY.md",
                issued_by="subagent",
                expires_at=future(),
            )

    def test_secrets_write_blocked_no_approval(self):
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write("secrets/prod_key.txt")

    def test_policies_write_blocked_no_approval(self):
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write("policies/access_control.json")

    def test_runtime_write_blocked_no_approval(self):
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write("runtime/agent_state.json")

    def test_model_routing_write_blocked_no_approval(self):
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write("model_routing.json")

    def test_tool_permissions_write_blocked_no_approval(self):
        with pytest.raises(ProtectedWriteBlocked):
            check_protected_write("tool_permissions.json")


# ═══════════════════════════════════════════════════════════════════════════════
# Audit log behaviour
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditLog:
    def test_every_blocked_write_is_logged(self):
        paths = ["IDENTITY.md", "config/x.json", ".env"]
        for p in paths:
            try:
                check_protected_write(p)
            except ProtectedWriteBlocked:
                pass
        log = get_audit_log()
        logged_paths = {e.path for e in log}
        assert logged_paths == set(paths)

    def test_approved_writes_are_logged(self):
        approval = make_approval(path_scope="IDENTITY.md")
        check_protected_write("IDENTITY.md", approval=approval)
        check_protected_write("workspace/notes.txt")
        log = get_audit_log()
        outcomes = {e.path: e.outcome for e in log}
        assert outcomes["IDENTITY.md"] == "approved"
        assert outcomes["workspace/notes.txt"] == "approved"

    def test_audit_log_is_most_recent_first(self):
        check_protected_write("workspace/a.txt")
        check_protected_write("workspace/b.txt")
        log = get_audit_log()
        assert log[0].path == "workspace/b.txt"
        assert log[1].path == "workspace/a.txt"

    def test_audit_entry_has_timestamp(self):
        check_protected_write("workspace/x.txt")
        entry = get_audit_log()[0]
        assert entry.timestamp  # non-empty
        dt = datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
        assert dt.tzinfo is not None

    def test_audit_entry_as_dict_complete(self):
        approval = make_approval(gate_word="OMEGA", path_scope="IDENTITY.md")
        check_protected_write("IDENTITY.md", approval=approval)
        entry = get_audit_log()[0]
        d = entry.as_dict()
        assert d["path"] == "IDENTITY.md"
        assert d["outcome"] == "approved"
        assert d["approval_gate_word_prefix"] == "OMEG"
        assert d["issued_by"] == "human"
        assert "entry_id" in d
        assert "timestamp" in d

    def test_blocked_entry_as_dict(self):
        try:
            check_protected_write("IDENTITY.md")
        except ProtectedWriteBlocked:
            pass
        entry = get_audit_log()[0]
        d = entry.as_dict()
        assert d["outcome"] == "blocked"
        assert d["approval_gate_word_prefix"] is None

    def test_clear_audit_log(self):
        check_protected_write("workspace/tmp.txt")
        clear_audit_log()
        assert get_audit_log() == []

    def test_audit_sink_called(self):
        received = []

        def sink(entry: AuditLogEntry) -> None:
            received.append(entry)

        from carapace.protected_paths import register_audit_sink
        register_audit_sink(sink)
        try:
            check_protected_write("workspace/out.txt")
            assert len(received) == 1
            assert received[0].outcome == "approved"
        finally:
            from carapace.protected_paths import _audit_sinks
            _audit_sinks.clear()

    def test_faulty_sink_does_not_interrupt_guard(self):
        """A crashing sink must not propagate its exception."""
        def bad_sink(entry: AuditLogEntry) -> None:
            raise RuntimeError("sink crash")

        from carapace.protected_paths import register_audit_sink, _audit_sinks
        register_audit_sink(bad_sink)
        try:
            entry = check_protected_write("workspace/safe.txt")
            assert entry.outcome == "approved"
        finally:
            _audit_sinks.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# Thread safety smoke test
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreadSafety:
    def test_concurrent_blocked_writes_all_logged(self):
        errors = []

        def write(path):
            try:
                check_protected_write(path)
            except ProtectedWriteBlocked:
                pass
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=write, args=(f"config/file_{i}.json",))
            for i in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(get_audit_log()) == 50
