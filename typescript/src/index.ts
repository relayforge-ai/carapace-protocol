/**
 * Carapace SDK v0.5.0 — Enforcement, Expiry, Versioning, Delegation, Protected Paths,
 * Epistemic Tracking, Compliance Profiles, Escalation Workflows,
 * Catalog Sync, and Signed Receipts
 */

export {
  enforce,
  enforceAll,
  enforceAny,
  extractCapabilityIds,
  hasCapability,
  CapabilityDenied,
  CardExpired,
  EnforcementPolicy,
  type CardLike,
  type Capability,
  type CapabilityCollection,
  type CapabilityInput,
  type PolicyRules,
} from './enforce';

export {
  makeExpiresAt,
  parseExpiresAt,
  checkExpiry,
  isExpired,
  timeRemaining,
  validateExpiryForVerify,
  ExpiryStatus,
  type ExpiryCheckResult,
} from './expiry';

export {
  validateVersionChain,
  prepareVersionFields,
  validateSupersedesRegistration,
  VersionChainError,
  OwnerMismatchError,
  VersionSequenceError,
  SupersedesNotFoundError,
  type VersionedCard,
  type VersionEntry,
  type VersionChain,
} from './versioning';

export {
  DelegationError,
  DelegationSigningError,
  ReplayDetected,
  CapabilityEscalation,
  DelegationExpired,
  RedelegationDepthExceeded,
  DelegatorCardInvalid,
  TTLExceedsDelegator,
  InMemoryNonceRegistry,
  createDelegation,
  verifyDelegation,
  verifyDelegationChain,
  signablePayload,
  validateCapabilitySubset,
  enforceDelegated,
  redelegate,
  MAX_CHAIN_DEPTH,
  DEFAULT_MAX_TTL_HOURS,
  DEFAULT_REDELEGATION_DEPTH,
  type DelegationToken,
  type DelegationVerifyResult,
  type CreateDelegationOptions,
  type ReplayChecker,
  type VerifyDelegationOptions,
} from './delegation';

export {
  DEFAULT_PROTECTED_PATTERNS,
  UNAUTHORIZED_SOURCES,
  ApprovalSourceForbidden,
  AuditLogEntry,
  ProtectedPathError,
  ProtectedWriteApproval,
  ProtectedWriteBlocked,
  checkProtectedWrite,
  clearAuditLog,
  getAuditLog,
  isProtectedPath,
  registerAuditSink,
  type AuditLogEntryData,
  type CheckProtectedWriteOptions,
  type ProtectedWriteApprovalOpts,
} from './protected_paths';

export {
  ConfidenceLevel,
  EpistemicLog,
  GENESIS_HASH,
  hashData,
  type EpistemicEntry,
  type Source,
} from './epistemic';

export {
  BUILTIN_PROFILES,
  evaluateCompliance,
  type ComplianceProfile,
  type ComplianceResult,
  type ComplianceViolation,
} from './compliance';

export {
  INDUSTRIAL_ESCALATION_POLICY,
  EscalationStatus,
  EscalationUrgency,
  checkAllEscalations,
  checkEscalation,
  type EscalationPolicy,
  type EscalationRequest,
  type EscalationTrigger,
} from './escalation';

// v0.5.0 — Catalog Sync
export {
  fetchCatalog,
  catalogGet,
  catalogIsActive,
  runGateCheck,
  type CatalogEntry,
  type CatalogState,
  type GateResult,
  type FetchCatalogOptions,
  type GateCheckOptions,
} from './catalog';

// v0.5.0 — Signed Receipts
export {
  createReceipt,
  verifyReceipt,
  postReceipt,
  type ReceiptPayload,
  type CreateReceiptOptions,
  type PostReceiptOptions,
} from './receipt';
