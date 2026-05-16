/**
 * Carapace v0.4 — Compliance Profiles (TypeScript)
 *
 * Named policy bundles for enterprise enforcement.
 * One-line policy answer instead of a configuration document.
 */

import type { CardLike } from './enforce';
import { hasCapability } from './enforce';
import { checkExpiry, ExpiryStatus } from './expiry';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ComplianceViolation {
  rule: string;
  description: string;
  severity: 'error' | 'warning';
}

export interface ComplianceResult {
  compliant: boolean;
  profileName: string;
  violations: ComplianceViolation[];
  warnings: ComplianceViolation[];
  checkedAt: string;
}

export interface ComplianceProfile {
  name: string;
  description?: string;
  requiredCapabilities?: string[];
  forbiddenCapabilities?: string[];
  requireExpiry?: boolean;
  maxTtlHours?: number;
  minVersion?: number;
  requireAttestationFrom?: string[];
  requireAttestationTypes?: string[];
  maxDelegationDepth?: number;
  requireDelegationTtlHours?: number;
  requireLegalEntity?: boolean;
  allowedFrameworks?: string[];
}

// ── Evaluation ───────────────────────────────────────────────────────────────

export function evaluateCompliance(
  card: CardLike & { card_version?: number; version?: number; framework?: string; expires_at?: string | null },
  profile: ComplianceProfile,
  options?: {
    attestations?: Array<{ attester_id?: string; type?: string }>;
    delegationChainDepth?: number;
    delegationTtlHours?: number;
    now?: Date;
  },
): ComplianceResult {
  const violations: ComplianceViolation[] = [];
  const warnings: ComplianceViolation[] = [];

  // Required capabilities
  for (const req of profile.requiredCapabilities ?? []) {
    if (!hasCapability(card, req)) {
      violations.push({ rule: 'required_capability', description: `Missing: ${req}`, severity: 'error' });
    }
  }

  // Forbidden capabilities
  for (const forbidden of profile.forbiddenCapabilities ?? []) {
    if (hasCapability(card, forbidden)) {
      violations.push({ rule: 'forbidden_capability', description: `Declares forbidden: ${forbidden}`, severity: 'error' });
    }
  }

  // Require expiry
  if (profile.requireExpiry) {
    const status = checkExpiry(card, { now: options?.now });
    if (status === ExpiryStatus.NO_EXPIRY) {
      violations.push({ rule: 'require_expiry', description: 'No expires_at field', severity: 'error' });
    } else if (status === ExpiryStatus.EXPIRED) {
      violations.push({ rule: 'card_expired', description: 'Card has expired', severity: 'error' });
    }
  }

  // Max TTL
  if (profile.maxTtlHours != null && card.expires_at) {
    const now = options?.now ?? new Date();
    const maxAllowed = new Date(now.getTime() + profile.maxTtlHours * 3600000);
    if (new Date(card.expires_at).getTime() > maxAllowed.getTime()) {
      violations.push({ rule: 'max_ttl', description: `TTL exceeds ${profile.maxTtlHours}h`, severity: 'error' });
    }
  }

  // Min version
  if (profile.minVersion != null) {
    const v = (card as any).card_version ?? (card as any).version ?? 1;
    if (typeof v === 'number' && v < profile.minVersion) {
      violations.push({ rule: 'min_version', description: `Version ${v} < ${profile.minVersion}`, severity: 'error' });
    }
  }

  // Attestations
  const attestations = options?.attestations ?? [];
  for (const req of profile.requireAttestationFrom ?? []) {
    if (!attestations.some((a) => a.attester_id === req)) {
      violations.push({ rule: 'require_attestation_from', description: `Missing from: ${req}`, severity: 'error' });
    }
  }
  for (const req of profile.requireAttestationTypes ?? []) {
    if (!attestations.some((a) => a.type === req)) {
      violations.push({ rule: 'require_attestation_type', description: `Missing type: ${req}`, severity: 'error' });
    }
  }

  // Delegation depth
  if (profile.maxDelegationDepth != null && options?.delegationChainDepth != null) {
    if (options.delegationChainDepth > profile.maxDelegationDepth) {
      violations.push({ rule: 'max_delegation_depth', description: `Depth ${options.delegationChainDepth} > ${profile.maxDelegationDepth}`, severity: 'error' });
    }
  }

  // Delegation TTL
  if (profile.requireDelegationTtlHours != null && options?.delegationTtlHours != null) {
    if (options.delegationTtlHours > profile.requireDelegationTtlHours) {
      violations.push({
        rule: 'delegation_ttl',
        description: `Delegation TTL ${options.delegationTtlHours}h > ${profile.requireDelegationTtlHours}h`,
        severity: 'error',
      });
    }
  }

  // Framework
  if (profile.allowedFrameworks && (card as any).framework) {
    if (!profile.allowedFrameworks.includes((card as any).framework)) {
      violations.push({ rule: 'allowed_frameworks', description: `Framework not allowed`, severity: 'error' });
    }
  }

  // Legal entity binding is a forward-compatible policy hook, not a shipped V0.4 verifier.
  if (profile.requireLegalEntity) {
    warnings.push({
      rule: 'require_legal_entity',
      description: 'Legal entity binding is not implemented in V0.4',
      severity: 'warning',
    });
  }

  return {
    compliant: violations.length === 0,
    profileName: profile.name,
    violations,
    warnings,
    checkedAt: new Date().toISOString(),
  };
}

// ── Built-in Profiles ────────────────────────────────────────────────────────

export const BUILTIN_PROFILES: Record<string, ComplianceProfile> = {
  'carapace-profile:isa-62443': {
    name: 'carapace-profile:isa-62443',
    description: 'ISA/IEC 62443 Industrial Automation',
    forbiddenCapabilities: ['carapace:execute:process_control'],
    requireExpiry: true,
    maxTtlHours: 8,
    maxDelegationDepth: 2,
    requireAttestationTypes: ['security_audit'],
  },
  'carapace-profile:hipaa': {
    name: 'carapace-profile:hipaa',
    description: 'HIPAA privacy compliance',
    forbiddenCapabilities: ['carapace:read:database'],
    requireExpiry: true,
    maxTtlHours: 24,
    requireAttestationTypes: ['privacy_audit'],
  },
  'carapace-profile:fedramp-moderate': {
    name: 'carapace-profile:fedramp-moderate',
    description: 'FedRAMP Moderate baseline',
    requireExpiry: true,
    maxTtlHours: 24,
    minVersion: 2,
    maxDelegationDepth: 3,
    requireAttestationTypes: ['security_audit', 'compliance_review'],
  },
  'carapace-profile:nerc-cip': {
    name: 'carapace-profile:nerc-cip',
    description: 'NERC CIP bulk electric system protection',
    forbiddenCapabilities: ['carapace:execute:process_control', 'carapace:admin:user_management'],
    requireExpiry: true,
    maxTtlHours: 4,
    maxDelegationDepth: 1,
    requireAttestationTypes: ['security_audit', 'nerc_cip_review'],
  },
  'carapace-profile:general-saas': {
    name: 'carapace-profile:general-saas',
    description: 'General SaaS baseline',
    forbiddenCapabilities: ['carapace:admin:user_management'],
    requireExpiry: true,
    maxTtlHours: 72,
  },
};
