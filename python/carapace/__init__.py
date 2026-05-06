"""Carapace v0.3 — Enforcement, Expiry, Versioning, Delegation"""

from carapace.enforce import (
    enforce,
    enforce_all,
    enforce_any,
    has_capability,
    require_capability,
    CapabilityDenied,
    CardExpired,
    EnforcementPolicy,
)
from carapace.expiry import (
    make_expires_at,
    check_expiry,
    is_expired,
    time_remaining,
    ExpiryStatus,
)
from carapace.versioning import (
    VersionChain,
    VersionEntry,
    validate_version_chain,
    prepare_version_fields,
    validate_supersedes_registration,
)
from carapace.delegation import (
    DelegationToken,
    DelegationVerifyResult,
    DelegationError,
    DelegationSigningError,
    SignatureInvalid,
    CapabilityEscalation,
    DelegationExpired,
    DelegationChainBroken,
    RedelegationDepthExceeded,
    DelegatorCardInvalid,
    TTLExceedsDelegator,
    create_delegation,
    verify_delegation,
    verify_delegation_chain,
    enforce_delegated,
    redelegate,
)

__version__ = "0.3.0"
