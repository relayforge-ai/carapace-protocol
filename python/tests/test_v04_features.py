"""
Tests for Carapace v0.4:
  - Epistemic Tracking
  - Compliance Profiles
  - Human-in-the-Loop Escalation

Run: pytest tests/test_v04_features.py -v
"""

import pytest
import json
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field


# ── Shared Fixtures ───────────────────────────────────────────────────────────

@dataclass
class MockOwner:
    public_key: str = "aa" * 32

@dataclass
class MockCard:
    id: str = "agent-uuid"
    capabilities: list[dict] = field(default_factory=list)
    expires_at: str | None = None
    owner: MockOwner = field(default_factory=MockOwner)
    status: str = "active"
    card_version: int = 1
    framework: str = "custom"

def make_card(caps=None, expires_at=None, version=1, framework="custom"):
    capabilities = [{"id": c, "name": c, "description": c} for c in (caps or [])]
    return MockCard(capabilities=capabilities, expires_at=expires_at,
                    card_version=version, framework=framework)

def future(hours=24):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()

def past(hours=1):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


# ═══════════════════════════════════════════════════════════════════════════════
# EPISTEMIC TRACKING TESTS
# ═══════════════════════════════════════════════════════════════════════════════

from carapace.epistemic import (
    EpistemicLog,
    EpistemicEntry,
    Source,
    ConfidenceLevel,
    hash_data,
    GENESIS_HASH,
)


class TestEpistemicLog:
    def test_empty_log(self):
        log = EpistemicLog(agent_id="test-agent")
        assert log.length == 0
        assert log.latest_hash == GENESIS_HASH
        valid, broken = log.verify_integrity()
        assert valid is True

    def test_single_entry(self):
        log = EpistemicLog(agent_id="test-agent")
        entry = log.record(
            action="classified_document",
            sources=[Source(agent_id="ocr-agent", data_hash="abc123")],
            confidence=0.85,
            reasoning="Matched template pattern",
        )
        assert log.length == 1
        assert entry.sequence == 1
        assert entry.confidence_level == ConfidenceLevel.HIGH
        assert entry.prev_hash == GENESIS_HASH
        assert entry.entry_hash != GENESIS_HASH

    def test_hash_chain_integrity(self):
        log = EpistemicLog(agent_id="test-agent")
        e1 = log.record(action="step1", confidence=0.9)
        e2 = log.record(action="step2", confidence=0.8)
        e3 = log.record(action="step3", confidence=0.7)

        assert e2.prev_hash == e1.entry_hash
        assert e3.prev_hash == e2.entry_hash
        valid, broken = log.verify_integrity()
        assert valid is True

    def test_tamper_detection(self):
        log = EpistemicLog(agent_id="test-agent")
        log.record(action="step1", confidence=0.9)
        log.record(action="step2", confidence=0.8)
        log.record(action="step3", confidence=0.7)

        # Tamper with entry 2
        log._entries[1].action = "TAMPERED"

        valid, broken = log.verify_integrity()
        assert valid is False
        assert broken == 2  # Sequence number of tampered entry

    def test_chain_break_detection(self):
        log = EpistemicLog(agent_id="test-agent")
        log.record(action="step1", confidence=0.9)
        log.record(action="step2", confidence=0.8)

        # Break the chain link
        log._entries[1].prev_hash = "0000" * 16

        valid, broken = log.verify_integrity()
        assert valid is False
        assert broken == 2

    def test_multiple_sources(self):
        log = EpistemicLog(agent_id="test-agent")
        entry = log.record(
            action="cross_referenced",
            sources=[
                Source(agent_id="agent-a", data_hash=hash_data("data_a")),
                Source(agent_id="agent-b", data_hash=hash_data("data_b")),
                Source(agent_id="agent-c", data_hash=hash_data("data_c")),
            ],
            confidence=0.95,
        )
        assert len(entry.sources) == 3
        assert entry.confidence_level == ConfidenceLevel.VERIFIED

    def test_confidence_levels(self):
        log = EpistemicLog(agent_id="test-agent")
        assert log.record(action="a", confidence=0.96).confidence_level == ConfidenceLevel.VERIFIED
        assert log.record(action="b", confidence=0.85).confidence_level == ConfidenceLevel.HIGH
        assert log.record(action="c", confidence=0.65).confidence_level == ConfidenceLevel.MEDIUM
        assert log.record(action="d", confidence=0.4).confidence_level == ConfidenceLevel.LOW
        assert log.record(action="e", confidence=0.1).confidence_level == ConfidenceLevel.UNVERIFIED

    def test_confidence_level_override(self):
        log = EpistemicLog(agent_id="test-agent")
        entry = log.record(
            action="operator_decision",
            confidence=0.5,
            confidence_level=ConfidenceLevel.HUMAN_OVERRIDE,
        )
        assert entry.confidence_level == ConfidenceLevel.HUMAN_OVERRIDE

    def test_delegation_tracking(self):
        log = EpistemicLog(agent_id="test-agent")
        entry = log.record(
            action="delegated_task",
            delegation_id="delegation-uuid-123",
            confidence=0.8,
        )
        assert entry.delegation_id == "delegation-uuid-123"

    def test_export_and_reimport(self):
        log = EpistemicLog(agent_id="test-agent")
        log.record(action="step1", confidence=0.9, reasoning="reason1")
        log.record(action="step2", confidence=0.8, reasoning="reason2")

        exported = log.export_json()
        restored = EpistemicLog.from_json(exported)

        assert restored.length == 2
        assert restored.agent_id == "test-agent"
        valid, _ = restored.verify_integrity()
        assert valid is True

    def test_query_by_action(self):
        log = EpistemicLog(agent_id="test-agent")
        log.record(action="read", confidence=0.9)
        log.record(action="write", confidence=0.8)
        log.record(action="read", confidence=0.7)

        results = log.query(action="read")
        assert len(results) == 2

    def test_query_by_source_agent(self):
        log = EpistemicLog(agent_id="test-agent")
        log.record(action="a", sources=[Source(agent_id="agent-x")], confidence=0.9)
        log.record(action="b", sources=[Source(agent_id="agent-y")], confidence=0.8)
        log.record(action="c", sources=[Source(agent_id="agent-x")], confidence=0.7)

        results = log.query(source_agent_id="agent-x")
        assert len(results) == 2

    def test_query_by_min_confidence(self):
        log = EpistemicLog(agent_id="test-agent")
        log.record(action="a", confidence=0.95)
        log.record(action="b", confidence=0.6)
        log.record(action="c", confidence=0.8)

        results = log.query(min_confidence=0.75)
        assert len(results) == 2

    def test_audit_trail_export(self):
        log = EpistemicLog(agent_id="test-agent")
        log.record(action="step1", confidence=0.9)
        audit = log.export_audit_trail()
        assert audit["integrity_valid"] is True
        assert audit["entry_count"] == 1
        assert audit["agent_id"] == "test-agent"

    def test_hash_data_utility(self):
        h1 = hash_data("hello")
        h2 = hash_data("hello")
        h3 = hash_data("world")
        assert h1 == h2
        assert h1 != h3
        assert len(h1) == 64  # SHA-256 hex


# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE PROFILE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

from carapace.compliance import (
    ComplianceProfile,
    ComplianceResult,
    evaluate_compliance,
    BUILTIN_PROFILES,
)


class TestComplianceProfiles:
    def test_compliant_card(self):
        profile = ComplianceProfile(
            name="test-profile",
            required_capabilities=["carapace:read:email"],
            require_expiry=True,
        )
        card = make_card(caps=["carapace:read:email"], expires_at=future(12))
        result = evaluate_compliance(card, profile)
        assert result.compliant is True
        assert len(result.violations) == 0

    def test_missing_required_capability(self):
        profile = ComplianceProfile(
            name="test",
            required_capabilities=["carapace:read:email", "carapace:write:email"],
        )
        card = make_card(caps=["carapace:read:email"])
        result = evaluate_compliance(card, profile)
        assert result.compliant is False
        assert any(v.rule == "required_capability" for v in result.violations)

    def test_forbidden_capability(self):
        profile = ComplianceProfile(
            name="test",
            forbidden_capabilities=["carapace:execute:process_control"],
        )
        card = make_card(caps=["carapace:execute:process_control"])
        result = evaluate_compliance(card, profile)
        assert result.compliant is False
        assert any(v.rule == "forbidden_capability" for v in result.violations)

    def test_require_expiry_no_expiry(self):
        profile = ComplianceProfile(name="test", require_expiry=True)
        card = make_card(caps=[])  # No expires_at
        result = evaluate_compliance(card, profile)
        assert result.compliant is False
        assert any(v.rule == "require_expiry" for v in result.violations)

    def test_require_expiry_expired_card(self):
        profile = ComplianceProfile(name="test", require_expiry=True)
        card = make_card(caps=[], expires_at=past(1))
        result = evaluate_compliance(card, profile)
        assert result.compliant is False
        assert any(v.rule == "card_expired" for v in result.violations)

    def test_max_ttl_exceeded(self):
        profile = ComplianceProfile(name="test", max_ttl_hours=8)
        card = make_card(caps=[], expires_at=future(24))  # 24h > 8h
        result = evaluate_compliance(card, profile)
        assert result.compliant is False
        assert any(v.rule == "max_ttl" for v in result.violations)

    def test_max_ttl_within_limit(self):
        profile = ComplianceProfile(name="test", max_ttl_hours=24)
        card = make_card(caps=[], expires_at=future(12))
        result = evaluate_compliance(card, profile)
        assert result.compliant is True

    def test_min_version(self):
        profile = ComplianceProfile(name="test", min_version=2)
        card = make_card(caps=[], version=1)
        result = evaluate_compliance(card, profile)
        assert result.compliant is False
        assert any(v.rule == "min_version" for v in result.violations)

    def test_min_version_met(self):
        profile = ComplianceProfile(name="test", min_version=2)
        card = make_card(caps=[], version=3)
        result = evaluate_compliance(card, profile)
        assert result.compliant is True

    def test_required_attestation(self):
        profile = ComplianceProfile(
            name="test",
            require_attestation_from=["security-auditor-uuid"],
        )
        card = make_card(caps=[])
        # No attestations provided
        result = evaluate_compliance(card, profile, attestations=[])
        assert result.compliant is False

        # With attestation
        result2 = evaluate_compliance(card, profile, attestations=[
            {"attester_id": "security-auditor-uuid", "type": "security_audit"}
        ])
        assert result2.compliant is True

    def test_required_attestation_types(self):
        profile = ComplianceProfile(
            name="test",
            require_attestation_types=["security_audit", "privacy_audit"],
        )
        card = make_card(caps=[])
        result = evaluate_compliance(card, profile, attestations=[
            {"attester_id": "x", "type": "security_audit"},
        ])
        assert result.compliant is False  # Missing privacy_audit

    def test_delegation_depth(self):
        profile = ComplianceProfile(name="test", max_delegation_depth=2)
        card = make_card(caps=[])
        result = evaluate_compliance(card, profile, delegation_chain_depth=5)
        assert result.compliant is False
        assert any(v.rule == "max_delegation_depth" for v in result.violations)

    def test_allowed_frameworks(self):
        profile = ComplianceProfile(name="test", allowed_frameworks=["langchain", "autogen"])
        card = make_card(caps=[], framework="custom")
        result = evaluate_compliance(card, profile)
        assert result.compliant is False
        assert any(v.rule == "allowed_frameworks" for v in result.violations)

    def test_builtin_isa_62443(self):
        profile = BUILTIN_PROFILES["carapace-profile:isa-62443"]
        # A card with process control should fail
        card = make_card(
            caps=["carapace:execute:process_control"],
            expires_at=future(4),
        )
        result = evaluate_compliance(card, profile)
        assert result.compliant is False

    def test_builtin_general_saas(self):
        profile = BUILTIN_PROFILES["carapace-profile:general-saas"]
        card = make_card(caps=["carapace:read:email"], expires_at=future(24))
        result = evaluate_compliance(card, profile)
        assert result.compliant is True

    def test_profile_serialization(self):
        profile = ComplianceProfile(
            name="test",
            required_capabilities=["cap:a"],
            require_expiry=True,
        )
        d = profile.to_dict()
        restored = ComplianceProfile.from_dict(d)
        assert restored.name == "test"
        assert restored.required_capabilities == ["cap:a"]

    def test_result_serialization(self):
        result = ComplianceResult(
            compliant=False,
            profile_name="test",
        )
        d = result.to_dict()
        assert d["compliant"] is False
        assert d["profile_name"] == "test"


# ═══════════════════════════════════════════════════════════════════════════════
# ESCALATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

from carapace.escalation import (
    EscalationPolicy,
    EscalationTrigger,
    EscalationRequest,
    EscalationRequired,
    EscalationDenied,
    EscalationStatus,
    EscalationUrgency,
    check_escalation,
    check_all_escalations,
    INDUSTRIAL_ESCALATION_POLICY,
)


def test_v04_public_entrypoint_exports():
    import carapace

    assert carapace.__version__ == "0.4.0"
    assert carapace.EpistemicLog is EpistemicLog
    assert carapace.ComplianceProfile is ComplianceProfile
    assert carapace.evaluate_compliance is evaluate_compliance
    assert carapace.EscalationPolicy is EscalationPolicy
    assert carapace.check_escalation is check_escalation
    assert "carapace-profile:general-saas" in carapace.BUILTIN_PROFILES


class TestEscalationTriggers:
    def test_single_capability_match(self):
        trigger = EscalationTrigger(capability="carapace:execute:process_control")
        assert trigger.matches(["carapace:execute:process_control"]) is True
        assert trigger.matches(["carapace:read:email"]) is False

    def test_wildcard_trigger(self):
        trigger = EscalationTrigger(capability="carapace:delete:*")
        assert trigger.matches(["carapace:delete:email"]) is True
        assert trigger.matches(["carapace:delete:database"]) is True
        assert trigger.matches(["carapace:read:email"]) is False

    def test_combination_trigger(self):
        trigger = EscalationTrigger(
            capabilities_combination=["carapace:read:database", "carapace:write:email"],
        )
        # Both present
        assert trigger.matches(["carapace:read:database", "carapace:write:email"]) is True
        # Only one present
        assert trigger.matches(["carapace:read:database"]) is False
        # Extra capabilities are fine
        assert trigger.matches([
            "carapace:read:database", "carapace:write:email", "carapace:read:calendar"
        ]) is True

    def test_custom_predicate(self):
        trigger = EscalationTrigger(
            predicate=lambda caps, ctx: ctx.get("risk_score", 0) > 0.8,
            reason="High risk score",
        )
        assert trigger.matches(["any"], {"risk_score": 0.9}) is True
        assert trigger.matches(["any"], {"risk_score": 0.5}) is False


class TestCheckEscalation:
    def test_no_escalation_needed(self):
        policy = EscalationPolicy(triggers=[
            EscalationTrigger(capability="carapace:delete:*", reason="delete")
        ])
        result = check_escalation(
            policy=policy,
            requested_capabilities=["carapace:read:email"],
            agent_id="agent-1",
        )
        assert result is None

    def test_escalation_triggered(self):
        policy = EscalationPolicy(triggers=[
            EscalationTrigger(
                capability="carapace:execute:process_control",
                reason="Requires operator approval",
                timeout_seconds=600,
                urgency=EscalationUrgency.CRITICAL,
            )
        ])
        result = check_escalation(
            policy=policy,
            requested_capabilities=["carapace:execute:process_control"],
            agent_id="agent-1",
            context="Adjusting valve setpoint",
        )
        assert result is not None
        assert result.reason == "Requires operator approval"
        assert result.urgency == EscalationUrgency.CRITICAL
        assert result.status == EscalationStatus.PENDING
        assert result.context == "Adjusting valve setpoint"

    def test_escalation_approval_flow(self):
        policy = EscalationPolicy(triggers=[
            EscalationTrigger(capability="carapace:delete:*", reason="delete")
        ])
        request = check_escalation(
            policy=policy,
            requested_capabilities=["carapace:delete:email"],
            agent_id="agent-1",
        )
        assert request is not None
        assert request.status == EscalationStatus.PENDING

        request.approve(approver_id="operator-1", notes="Confirmed safe")
        assert request.status == EscalationStatus.APPROVED
        assert request.resolved_by == "operator-1"

    def test_escalation_denial_flow(self):
        policy = EscalationPolicy(triggers=[
            EscalationTrigger(capability="carapace:delete:*", reason="delete")
        ])
        request = check_escalation(
            policy=policy,
            requested_capabilities=["carapace:delete:database"],
            agent_id="agent-1",
        )
        request.deny(denier_id="supervisor-1", notes="Not authorized")
        assert request.status == EscalationStatus.DENIED

    def test_check_all_escalations(self):
        policy = EscalationPolicy(triggers=[
            EscalationTrigger(capability="carapace:delete:*", reason="delete ops"),
            EscalationTrigger(
                capabilities_combination=["carapace:read:database", "carapace:write:email"],
                reason="data exfil risk",
            ),
        ])
        results = check_all_escalations(
            policy=policy,
            requested_capabilities=[
                "carapace:delete:email",
                "carapace:read:database",
                "carapace:write:email",
            ],
        )
        assert len(results) == 2

    def test_webhook_payload(self):
        policy = EscalationPolicy(triggers=[
            EscalationTrigger(capability="carapace:delete:*", reason="delete")
        ])
        request = check_escalation(
            policy=policy,
            requested_capabilities=["carapace:delete:email"],
            agent_id="agent-1",
        )
        payload = request.to_webhook_payload()
        assert payload["type"] == "carapace_escalation"
        assert payload["version"] == "0.4"
        assert "approve_url" in payload["actions"]
        assert "deny_url" in payload["actions"]

    def test_industrial_policy(self):
        request = check_escalation(
            policy=INDUSTRIAL_ESCALATION_POLICY,
            requested_capabilities=["carapace:execute:process_control"],
            agent_id="agent-1",
        )
        assert request is not None
        assert request.urgency == EscalationUrgency.CRITICAL
