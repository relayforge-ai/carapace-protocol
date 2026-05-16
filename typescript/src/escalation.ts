/**
 * Carapace v0.4 — Human-in-the-Loop Escalation (TypeScript)
 *
 * MOC (Management of Change) process for agent operations.
 */

// ── Types ────────────────────────────────────────────────────────────────────

export enum EscalationStatus {
  PENDING = 'pending',
  APPROVED = 'approved',
  DENIED = 'denied',
  TIMED_OUT = 'timed_out',
  CANCELLED = 'cancelled',
}

export enum EscalationUrgency {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export interface EscalationTrigger {
  capability?: string;
  capabilitiesCombination?: string[];
  reason: string;
  timeoutSeconds?: number;
  urgency?: EscalationUrgency;
  webhookUrl?: string;
  requiredApprovers?: string[];
  minApprovals?: number;
  predicate?: (caps: string[], context: Record<string, any>) => boolean;
}

export interface EscalationRequest {
  id: string;
  agentId: string;
  requestedCapabilities: string[];
  triggeredBy: EscalationTrigger;
  reason: string;
  urgency: EscalationUrgency;
  context: string | null;
  timeoutSeconds: number;
  status: EscalationStatus;
  createdAt: string;
  resolvedAt: string | null;
  resolvedBy: string | null;
  approvalNotes: string | null;
}

export interface EscalationPolicy {
  name?: string;
  description?: string;
  triggers: EscalationTrigger[];
  defaultWebhookUrl?: string;
  blocking?: boolean;
}

// ── Matching ─────────────────────────────────────────────────────────────────

function triggerMatches(
  trigger: EscalationTrigger,
  requestedCaps: string[],
  context?: Record<string, any>,
): boolean {
  // Single capability
  if (trigger.capability) {
    for (const req of requestedCaps) {
      if (req === trigger.capability) return true;
      if (trigger.capability.endsWith(':*') && req.startsWith(trigger.capability.slice(0, -1))) return true;
      if (req.endsWith(':*') && trigger.capability.startsWith(req.slice(0, -1))) return true;
    }
  }

  // Combination
  if (trigger.capabilitiesCombination) {
    const allMatched = trigger.capabilitiesCombination.every((combo) =>
      requestedCaps.some((req) => {
        if (req === combo) return true;
        if (combo.endsWith(':*') && req.startsWith(combo.slice(0, -1))) return true;
        if (req.endsWith(':*') && combo.startsWith(req.slice(0, -1))) return true;
        return false;
      }),
    );
    if (allMatched) return true;
  }

  // Predicate
  if (trigger.predicate) {
    return trigger.predicate(requestedCaps, context ?? {});
  }

  return false;
}

// ── UUID ─────────────────────────────────────────────────────────────────────

function uuid(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

// ── Check Functions ──────────────────────────────────────────────────────────

export function checkEscalation(
  policy: EscalationPolicy,
  requestedCapabilities: string[],
  agentId?: string,
  context?: string,
  contextData?: Record<string, any>,
): EscalationRequest | null {
  for (const trigger of policy.triggers) {
    if (triggerMatches(trigger, requestedCapabilities, contextData)) {
      return {
        id: uuid(),
        agentId: agentId ?? '',
        requestedCapabilities,
        triggeredBy: trigger,
        reason: trigger.reason,
        urgency: trigger.urgency ?? EscalationUrgency.MEDIUM,
        context: context ?? null,
        timeoutSeconds: trigger.timeoutSeconds ?? 300,
        status: EscalationStatus.PENDING,
        createdAt: new Date().toISOString(),
        resolvedAt: null,
        resolvedBy: null,
        approvalNotes: null,
      };
    }
  }
  return null;
}

export function checkAllEscalations(
  policy: EscalationPolicy,
  requestedCapabilities: string[],
  agentId?: string,
  context?: string,
  contextData?: Record<string, any>,
): EscalationRequest[] {
  return policy.triggers
    .filter((t) => triggerMatches(t, requestedCapabilities, contextData))
    .map((trigger) => ({
      id: uuid(),
      agentId: agentId ?? '',
      requestedCapabilities,
      triggeredBy: trigger,
      reason: trigger.reason,
      urgency: trigger.urgency ?? EscalationUrgency.MEDIUM,
      context: context ?? null,
      timeoutSeconds: trigger.timeoutSeconds ?? 300,
      status: EscalationStatus.PENDING,
      createdAt: new Date().toISOString(),
      resolvedAt: null,
      resolvedBy: null,
      approvalNotes: null,
    }));
}

// ── Built-in Policy ──────────────────────────────────────────────────────────

export const INDUSTRIAL_ESCALATION_POLICY: EscalationPolicy = {
  name: 'industrial-safety',
  description: 'Process safety escalation — MOC equivalent for agent operations',
  blocking: true,
  triggers: [
    {
      capability: 'carapace:execute:process_control',
      reason: 'Process control actions require operator approval (MOC)',
      timeoutSeconds: 600,
      urgency: EscalationUrgency.CRITICAL,
    },
    {
      capability: 'carapace:write:safety_system',
      reason: 'Safety system modifications require supervisor approval',
      timeoutSeconds: 300,
      urgency: EscalationUrgency.CRITICAL,
      minApprovals: 2,
    },
    {
      capability: 'carapace:delete:*',
      reason: 'All delete operations require approval',
      timeoutSeconds: 300,
      urgency: EscalationUrgency.HIGH,
    },
    {
      capabilitiesCombination: ['carapace:read:database', 'carapace:write:email'],
      reason: 'Data read + email send — data exfiltration risk',
      timeoutSeconds: 300,
      urgency: EscalationUrgency.HIGH,
    },
  ],
};
