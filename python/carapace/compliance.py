"""
Carapace v0.4 — Compliance Profiles

A compliance profile is a named set of capability and attestation requirements
that a host system declares as a policy. An agent either meets the profile
or it doesn't.

This gives enterprise buyers a one-line policy answer instead of a
configuration document. It also gives RelayForge a professional services
opportunity — helping organizations define custom profiles.

Usage:
    from carapace.compliance import (
        ComplianceProfile,
        evaluate_compliance,
        BUILTIN_PROFILES,
    )

    # Use a built-in profile
    profile = BUILTIN_PROFILES["carapace-profile:hipaa"]
    result = evaluate_compliance(card, profile)

    if result.compliant:
        grant_access(card)
    else:
        print(f"Non-compliant: {result.violations}")

    # Define a custom profile
    custom = ComplianceProfile(
        name="acme-internal",
        description="ACME Corp internal agent policy",
        required_capabilities=["carapace:read:database"],
        forbidden_capabilities=["carapace:execute:process_control"],
        max_ttl_hours=24,
        require_expiry=True,
        min_version=2,
        require_attestation_from=["security-auditor-uuid"],
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from carapace.enforce import has_capability, _extract_capability_ids
from carapace.expiry import parse_expires_at, check_expiry, ExpiryStatus


# ── Types ─────────────────────────────────────────────────────────────────────

@dataclass
class ComplianceViolation:
    """A single compliance check failure."""
    rule: str                   # Which rule was violated
    description: str            # Human-readable explanation
    severity: str = "error"     # "error" (blocks), "warning" (flags)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "description": self.description,
            "severity": self.severity,
        }


@dataclass
class ComplianceResult:
    """Result of evaluating a card against a compliance profile."""
    compliant: bool
    profile_name: str
    violations: list[ComplianceViolation] = field(default_factory=list)
    warnings: list[ComplianceViolation] = field(default_factory=list)
    checked_at: str = ""

    def __post_init__(self):
        if not self.checked_at:
            self.checked_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "compliant": self.compliant,
            "profile_name": self.profile_name,
            "violations": [v.to_dict() for v in self.violations],
            "warnings": [w.to_dict() for w in self.warnings],
            "checked_at": self.checked_at,
        }


# ── Compliance Profile ────────────────────────────────────────────────────────

@dataclass
class ComplianceProfile:
    """
    A named set of requirements that an agent card must satisfy.

    All fields are optional — only specified rules are enforced.
    """
    name: str
    description: str = ""

    # ── Capability rules ──────────────────────────────────────────────────
    required_capabilities: list[str] = field(default_factory=list)
    """Card MUST declare all of these capabilities."""

    forbidden_capabilities: list[str] = field(default_factory=list)
    """Card MUST NOT declare any of these capabilities."""

    # ── TTL / Expiry rules ────────────────────────────────────────────────
    require_expiry: bool = False
    """Card MUST have an expires_at field (no immortal cards)."""

    max_ttl_hours: float | None = None
    """Card's TTL must not exceed this many hours from now."""

    # ── Version rules ─────────────────────────────────────────────────────
    min_version: int | None = None
    """Card's card_version must be at least this."""

    # ── Attestation rules ─────────────────────────────────────────────────
    require_attestation_from: list[str] = field(default_factory=list)
    """Card must have valid attestations from these evaluator IDs."""

    require_attestation_types: list[str] = field(default_factory=list)
    """Card must have attestations of these types (e.g., 'security_audit')."""

    # ── Delegation rules ──────────────────────────────────────────────────
    max_delegation_depth: int | None = None
    """If operating under delegation, chain depth must not exceed this."""

    require_delegation_ttl_hours: float | None = None
    """Delegations must expire within this many hours."""

    # ── Owner rules ───────────────────────────────────────────────────────
    require_legal_entity: bool = False
    """Card's owner must be bound to a legal entity (v1.0 feature)."""

    allowed_frameworks: list[str] | None = None
    """If set, card's framework must be in this list."""

    # ── Custom rules ──────────────────────────────────────────────────────
    custom_rules: list[dict[str, Any]] = field(default_factory=list)
    """Extensible custom rules for organization-specific policies."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "required_capabilities": self.required_capabilities,
            "forbidden_capabilities": self.forbidden_capabilities,
            "require_expiry": self.require_expiry,
            "max_ttl_hours": self.max_ttl_hours,
            "min_version": self.min_version,
            "require_attestation_from": self.require_attestation_from,
            "require_attestation_types": self.require_attestation_types,
            "max_delegation_depth": self.max_delegation_depth,
            "require_delegation_ttl_hours": self.require_delegation_ttl_hours,
            "require_legal_entity": self.require_legal_entity,
            "allowed_frameworks": self.allowed_frameworks,
            "custom_rules": self.custom_rules,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ComplianceProfile:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ── Evaluation Engine ─────────────────────────────────────────────────────────

def evaluate_compliance(
    card: Any,
    profile: ComplianceProfile,
    *,
    attestations: list[dict[str, Any]] | None = None,
    delegation_chain_depth: int | None = None,
    delegation_ttl_hours: float | None = None,
    now: datetime | None = None,
) -> ComplianceResult:
    """
    Evaluate a card against a compliance profile.

    Args:
        card: AgentCard or card-like object.
        profile: The compliance profile to evaluate against.
        attestations: List of attestation objects attached to the card.
        delegation_chain_depth: Current delegation chain depth (if applicable).
        delegation_ttl_hours: Current delegation TTL in hours.
        now: Override current time (for testing).

    Returns:
        ComplianceResult with violations and warnings.
    """
    violations: list[ComplianceViolation] = []
    warnings: list[ComplianceViolation] = []
    current = now or datetime.now(timezone.utc)

    card_caps = _extract_capability_ids(card)

    # ── Required capabilities ─────────────────────────────────────────────
    for req in profile.required_capabilities:
        if not has_capability(card, req):
            violations.append(ComplianceViolation(
                rule="required_capability",
                description=f"Missing required capability: {req}",
            ))

    # ── Forbidden capabilities ────────────────────────────────────────────
    for forbidden in profile.forbidden_capabilities:
        if has_capability(card, forbidden):
            violations.append(ComplianceViolation(
                rule="forbidden_capability",
                description=f"Declares forbidden capability: {forbidden}",
            ))

    # ── Expiry required ───────────────────────────────────────────────────
    if profile.require_expiry:
        expiry_status = check_expiry(card, now=current)
        if expiry_status == ExpiryStatus.NO_EXPIRY:
            violations.append(ComplianceViolation(
                rule="require_expiry",
                description="Card has no expires_at field — profile requires expiry",
            ))
        elif expiry_status == ExpiryStatus.EXPIRED:
            violations.append(ComplianceViolation(
                rule="card_expired",
                description="Card has expired",
            ))

    # ── Max TTL ───────────────────────────────────────────────────────────
    if profile.max_ttl_hours is not None:
        raw_expiry = (
            card.get("expires_at") if isinstance(card, dict)
            else getattr(card, "expires_at", None)
        )
        exp_dt = parse_expires_at(raw_expiry)
        if exp_dt:
            max_allowed = current + timedelta(hours=profile.max_ttl_hours)
            if exp_dt > max_allowed:
                violations.append(ComplianceViolation(
                    rule="max_ttl",
                    description=(
                        f"Card TTL exceeds maximum {profile.max_ttl_hours}h — "
                        f"expires at {raw_expiry}"
                    ),
                ))
        elif profile.require_expiry:
            pass  # Already caught above
        else:
            warnings.append(ComplianceViolation(
                rule="max_ttl",
                description="No expiry set — cannot verify TTL compliance",
                severity="warning",
            ))

    # ── Minimum version ───────────────────────────────────────────────────
    if profile.min_version is not None:
        card_version = (
            card.get("card_version", card.get("version", 1))
            if isinstance(card, dict)
            else getattr(card, "card_version", getattr(card, "version", 1))
        )
        if isinstance(card_version, int) and card_version < profile.min_version:
            violations.append(ComplianceViolation(
                rule="min_version",
                description=(
                    f"Card version {card_version} is below minimum {profile.min_version}"
                ),
            ))

    # ── Attestation requirements ──────────────────────────────────────────
    attestations = attestations or []

    if profile.require_attestation_from:
        attester_ids = {a.get("attester_id") for a in attestations}
        for required_attester in profile.require_attestation_from:
            if required_attester not in attester_ids:
                violations.append(ComplianceViolation(
                    rule="require_attestation_from",
                    description=f"Missing attestation from: {required_attester}",
                ))

    if profile.require_attestation_types:
        attestation_types = {a.get("type") for a in attestations}
        for required_type in profile.require_attestation_types:
            if required_type not in attestation_types:
                violations.append(ComplianceViolation(
                    rule="require_attestation_type",
                    description=f"Missing attestation type: {required_type}",
                ))

    # ── Delegation depth ──────────────────────────────────────────────────
    if profile.max_delegation_depth is not None and delegation_chain_depth is not None:
        if delegation_chain_depth > profile.max_delegation_depth:
            violations.append(ComplianceViolation(
                rule="max_delegation_depth",
                description=(
                    f"Delegation depth {delegation_chain_depth} exceeds "
                    f"maximum {profile.max_delegation_depth}"
                ),
            ))

    # ── Delegation TTL ────────────────────────────────────────────────────
    if profile.require_delegation_ttl_hours is not None and delegation_ttl_hours is not None:
        if delegation_ttl_hours > profile.require_delegation_ttl_hours:
            violations.append(ComplianceViolation(
                rule="delegation_ttl",
                description=(
                    f"Delegation TTL {delegation_ttl_hours}h exceeds "
                    f"maximum {profile.require_delegation_ttl_hours}h"
                ),
            ))

    # ── Framework restriction ─────────────────────────────────────────────
    if profile.allowed_frameworks is not None:
        framework = (
            card.get("framework") if isinstance(card, dict)
            else getattr(card, "framework", None)
        )
        if framework and framework not in profile.allowed_frameworks:
            violations.append(ComplianceViolation(
                rule="allowed_frameworks",
                description=(
                    f"Framework '{framework}' not in allowed list: "
                    f"{profile.allowed_frameworks}"
                ),
            ))

    # ── Legal entity binding (future — always warn if required) ───────────
    if profile.require_legal_entity:
        warnings.append(ComplianceViolation(
            rule="require_legal_entity",
            description="Legal entity binding not yet implemented (v1.0)",
            severity="warning",
        ))

    # ── Result ────────────────────────────────────────────────────────────
    compliant = len(violations) == 0
    return ComplianceResult(
        compliant=compliant,
        profile_name=profile.name,
        violations=violations,
        warnings=warnings,
    )


# ── Built-in Profiles ────────────────────────────────────────────────────────

BUILTIN_PROFILES: dict[str, ComplianceProfile] = {
    "carapace-profile:isa-62443": ComplianceProfile(
        name="carapace-profile:isa-62443",
        description=(
            "ISA/IEC 62443 Industrial Automation — no process control execution "
            "without Tier 2 attestation, mandatory expiry, max 8h TTL"
        ),
        forbidden_capabilities=["carapace:execute:process_control"],
        require_expiry=True,
        max_ttl_hours=8,
        max_delegation_depth=2,
        require_attestation_types=["security_audit"],
    ),

    "carapace-profile:hipaa": ComplianceProfile(
        name="carapace-profile:hipaa",
        description=(
            "HIPAA — no database read without privacy attestation, "
            "mandatory expiry, max 24h TTL"
        ),
        forbidden_capabilities=["carapace:read:database"],
        require_expiry=True,
        max_ttl_hours=24,
        require_attestation_types=["privacy_audit"],
    ),

    "carapace-profile:fedramp-moderate": ComplianceProfile(
        name="carapace-profile:fedramp-moderate",
        description=(
            "FedRAMP Moderate — max 24h TTL, require security attestation, "
            "minimum card version 2, max delegation depth 3"
        ),
        require_expiry=True,
        max_ttl_hours=24,
        min_version=2,
        max_delegation_depth=3,
        require_attestation_types=["security_audit", "compliance_review"],
    ),

    "carapace-profile:nerc-cip": ComplianceProfile(
        name="carapace-profile:nerc-cip",
        description=(
            "NERC CIP — bulk electric system protection. No process control "
            "or admin capabilities, 4h TTL, security attestation required."
        ),
        forbidden_capabilities=[
            "carapace:execute:process_control",
            "carapace:admin:user_management",
        ],
        require_expiry=True,
        max_ttl_hours=4,
        max_delegation_depth=1,
        require_attestation_types=["security_audit", "nerc_cip_review"],
    ),

    "carapace-profile:general-saas": ComplianceProfile(
        name="carapace-profile:general-saas",
        description="General SaaS — mandatory expiry, 72h TTL, no admin.",
        forbidden_capabilities=["carapace:admin:user_management"],
        require_expiry=True,
        max_ttl_hours=72,
    ),
}
