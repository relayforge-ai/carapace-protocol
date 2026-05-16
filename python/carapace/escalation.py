"""
Carapace v0.4 — Human-in-the-Loop Escalation Triggers

For safety-critical applications, some capability combinations should require
human confirmation before execution. This is directly analogous to Management
of Change (MOC) processes in process safety — before you change a process
parameter, a human signs off.

Usage:
    from carapace.escalation import (
        EscalationPolicy,
        EscalationTrigger,
        EscalationRequest,
        check_escalation,
    )

    # Define escalation policy
    policy = EscalationPolicy(
        triggers=[
            EscalationTrigger(
                capability="carapace:execute:process_control",
                reason="Process control actions require operator approval",
                timeout_seconds=300,
            ),
            EscalationTrigger(
                capability="carapace:delete:*",
                reason="All delete operations require approval",
            ),
            EscalationTrigger(
                capabilities_combination=["carapace:read:database", "carapace:write:email"],
                reason="Reading DB and sending email together requires approval (data exfiltration risk)",
            ),
        ]
    )

    # Check if an action requires escalation
    request = check_escalation(
        policy=policy,
        requested_capabilities=["carapace:execute:process_control"],
        agent_id="agent-uuid",
        context="Adjusting valve setpoint on reactor 3",
    )

    if request:
        # Send to approval webhook / queue
        approval = await submit_escalation(request)
        if not approval.approved:
            raise EscalationDenied(request)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Sequence

from carapace.enforce import has_capability


# ── Types ─────────────────────────────────────────────────────────────────────

class EscalationStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class EscalationUrgency(Enum):
    LOW = "low"              # Can wait hours
    MEDIUM = "medium"        # Should be handled within minutes
    HIGH = "high"            # Needs immediate attention
    CRITICAL = "critical"    # Blocks safety-critical operation


# ── Exceptions ────────────────────────────────────────────────────────────────

class EscalationRequired(Exception):
    """Raised when an action requires human approval."""
    def __init__(self, request: EscalationRequest):
        self.request = request
        super().__init__(
            f"Human approval required: {request.reason} "
            f"(escalation {request.id})"
        )


class EscalationDenied(Exception):
    """Raised when a human denied the escalation."""
    def __init__(self, request: EscalationRequest, denier: str | None = None):
        self.request = request
        self.denier = denier
        super().__init__(
            f"Escalation denied by {denier or 'operator'}: {request.reason}"
        )


class EscalationTimedOut(Exception):
    """Raised when escalation approval wasn't received in time."""
    def __init__(self, request: EscalationRequest):
        self.request = request
        super().__init__(
            f"Escalation timed out after {request.timeout_seconds}s: {request.reason}"
        )


# ── Trigger ───────────────────────────────────────────────────────────────────

@dataclass
class EscalationTrigger:
    """
    A single condition that triggers human-in-the-loop escalation.

    Can match on:
    - A single capability being exercised
    - A combination of capabilities being exercised together
    - A custom predicate function
    """
    # Single capability trigger (supports wildcards)
    capability: str | None = None

    # Combination trigger — ALL must be present to trigger
    capabilities_combination: list[str] | None = None

    # Human-readable reason shown to the approver
    reason: str = ""

    # How long to wait for approval before timing out
    timeout_seconds: int = 300  # 5 minutes

    # Urgency level
    urgency: EscalationUrgency = EscalationUrgency.MEDIUM

    # Custom predicate: fn(requested_capabilities, context) -> bool
    predicate: Callable[[list[str], dict[str, Any]], bool] | None = None

    # Notification webhook URL (where to send the approval request)
    webhook_url: str | None = None

    # Required approver IDs (if specific people must approve)
    required_approvers: list[str] = field(default_factory=list)

    # Minimum number of approvals needed (for multi-party approval)
    min_approvals: int = 1

    def matches(
        self,
        requested_capabilities: list[str],
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Check if this trigger matches the requested capabilities."""
        # Single capability check
        if self.capability:
            for req in requested_capabilities:
                if req == self.capability:
                    return True
                # Wildcard in trigger
                if self.capability.endswith(":*"):
                    prefix = self.capability[:-1]
                    if req.startswith(prefix):
                        return True
                # Wildcard in requested
                if req.endswith(":*"):
                    prefix = req[:-1]
                    if self.capability.startswith(prefix):
                        return True

        # Combination check — all must be present
        if self.capabilities_combination:
            matched_all = True
            for combo_cap in self.capabilities_combination:
                found = False
                for req in requested_capabilities:
                    if req == combo_cap:
                        found = True
                        break
                    if combo_cap.endswith(":*") and req.startswith(combo_cap[:-1]):
                        found = True
                        break
                    if req.endswith(":*") and combo_cap.startswith(req[:-1]):
                        found = True
                        break
                if not found:
                    matched_all = False
                    break
            if matched_all:
                return True

        # Custom predicate
        if self.predicate:
            return self.predicate(requested_capabilities, context or {})

        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "capabilities_combination": self.capabilities_combination,
            "reason": self.reason,
            "timeout_seconds": self.timeout_seconds,
            "urgency": self.urgency.value,
            "webhook_url": self.webhook_url,
            "required_approvers": self.required_approvers,
            "min_approvals": self.min_approvals,
        }


# ── Escalation Request ───────────────────────────────────────────────────────

@dataclass
class EscalationRequest:
    """
    A request for human approval, generated when a trigger matches.
    This is what gets sent to the webhook or displayed to the operator.
    """
    id: str
    agent_id: str
    requested_capabilities: list[str]
    triggered_by: EscalationTrigger
    reason: str
    urgency: EscalationUrgency
    context: str | None
    timeout_seconds: int
    status: EscalationStatus = EscalationStatus.PENDING
    created_at: str = ""
    resolved_at: str | None = None
    resolved_by: str | None = None
    approval_notes: str | None = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def approve(self, approver_id: str, notes: str | None = None) -> None:
        """Mark this escalation as approved."""
        self.status = EscalationStatus.APPROVED
        self.resolved_at = datetime.now(timezone.utc).isoformat()
        self.resolved_by = approver_id
        self.approval_notes = notes

    def deny(self, denier_id: str, notes: str | None = None) -> None:
        """Mark this escalation as denied."""
        self.status = EscalationStatus.DENIED
        self.resolved_at = datetime.now(timezone.utc).isoformat()
        self.resolved_by = denier_id
        self.approval_notes = notes

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "requested_capabilities": self.requested_capabilities,
            "reason": self.reason,
            "urgency": self.urgency.value,
            "context": self.context,
            "timeout_seconds": self.timeout_seconds,
            "status": self.status.value,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "approval_notes": self.approval_notes,
        }

    def to_webhook_payload(self) -> dict[str, Any]:
        """
        Standardized webhook payload for external approval systems.
        Follows a common pattern that Slack bots, email handlers,
        and custom dashboards can consume.
        """
        return {
            "type": "carapace_escalation",
            "version": "0.4",
            "escalation": self.to_dict(),
            "actions": {
                "approve_url": f"/aria/v1/escalations/{self.id}/approve",
                "deny_url": f"/aria/v1/escalations/{self.id}/deny",
            },
        }


# ── Policy ────────────────────────────────────────────────────────────────────

@dataclass
class EscalationPolicy:
    """
    A collection of escalation triggers that define when human approval is needed.

    Attach to a host system, a compliance profile, or a specific agent deployment.
    """
    triggers: list[EscalationTrigger] = field(default_factory=list)
    name: str = ""
    description: str = ""

    # Default webhook for all triggers that don't specify one
    default_webhook_url: str | None = None

    # If True, ANY matching trigger blocks execution until approved.
    # If False, triggers only generate warnings (audit-only mode).
    blocking: bool = True

    def add_trigger(self, trigger: EscalationTrigger) -> None:
        self.triggers.append(trigger)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "triggers": [t.to_dict() for t in self.triggers],
            "default_webhook_url": self.default_webhook_url,
            "blocking": self.blocking,
        }


# ── Check Function ────────────────────────────────────────────────────────────

def check_escalation(
    policy: EscalationPolicy,
    requested_capabilities: list[str],
    agent_id: str = "",
    context: str | None = None,
    context_data: dict[str, Any] | None = None,
) -> EscalationRequest | None:
    """
    Check if the requested capabilities trigger any escalation rules.

    Returns an EscalationRequest if approval is needed, or None if
    the action can proceed without escalation.

    Note: This checks the FIRST matching trigger. If multiple triggers
    match, the first one wins (order your policy accordingly).
    """
    for trigger in policy.triggers:
        if trigger.matches(requested_capabilities, context_data):
            return EscalationRequest(
                id=str(uuid.uuid4()),
                agent_id=agent_id,
                requested_capabilities=requested_capabilities,
                triggered_by=trigger,
                reason=trigger.reason,
                urgency=trigger.urgency,
                context=context,
                timeout_seconds=trigger.timeout_seconds,
            )
    return None


def check_all_escalations(
    policy: EscalationPolicy,
    requested_capabilities: list[str],
    agent_id: str = "",
    context: str | None = None,
    context_data: dict[str, Any] | None = None,
) -> list[EscalationRequest]:
    """
    Check ALL matching triggers (not just the first).
    Returns a list of all escalation requests needed.
    """
    results = []
    for trigger in policy.triggers:
        if trigger.matches(requested_capabilities, context_data):
            results.append(EscalationRequest(
                id=str(uuid.uuid4()),
                agent_id=agent_id,
                requested_capabilities=requested_capabilities,
                triggered_by=trigger,
                reason=trigger.reason,
                urgency=trigger.urgency,
                context=context,
                timeout_seconds=trigger.timeout_seconds,
            ))
    return results


# ── Pre-built Policies ────────────────────────────────────────────────────────

INDUSTRIAL_ESCALATION_POLICY = EscalationPolicy(
    name="industrial-safety",
    description="Process safety escalation — MOC equivalent for agent operations",
    blocking=True,
    triggers=[
        EscalationTrigger(
            capability="carapace:execute:process_control",
            reason="Process control actions require operator approval (MOC)",
            timeout_seconds=600,
            urgency=EscalationUrgency.CRITICAL,
        ),
        EscalationTrigger(
            capability="carapace:write:safety_system",
            reason="Safety system modifications require supervisor approval",
            timeout_seconds=300,
            urgency=EscalationUrgency.CRITICAL,
            min_approvals=2,
        ),
        EscalationTrigger(
            capability="carapace:delete:*",
            reason="All delete operations require approval",
            timeout_seconds=300,
            urgency=EscalationUrgency.HIGH,
        ),
        EscalationTrigger(
            capabilities_combination=[
                "carapace:read:database",
                "carapace:write:email",
            ],
            reason="Data read + email send combination — data exfiltration risk",
            timeout_seconds=300,
            urgency=EscalationUrgency.HIGH,
        ),
    ],
)
