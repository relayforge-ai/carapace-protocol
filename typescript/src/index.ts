/**
 * Carapace SDK v0.2 — Enforcement, Expiry, Versioning
 */

export {
  enforce,
  enforceAll,
  enforceAny,
  hasCapability,
  CapabilityDenied,
  CardExpired,
  EnforcementPolicy,
  type CardLike,
  type Capability,
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
