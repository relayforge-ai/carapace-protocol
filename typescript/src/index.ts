/**
 * Carapace SDK v0.3 — Enforcement, Expiry, Versioning, Delegation, Protected Paths
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
