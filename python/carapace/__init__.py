"""Carapace v0.4 — Enforcement, Expiry, Versioning, Delegation, V0.4 Trust Workflows"""

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
    InMemoryNonceRegistry,
    DelegationError,
    DelegationSigningError,
    ReplayDetected,
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
from carapace.protected_paths import (
    DEFAULT_PROTECTED_PATTERNS,
    UNAUTHORIZED_SOURCES,
    ApprovalSourceForbidden,
    AuditLogEntry,
    ProtectedPathError,
    ProtectedWriteApproval,
    ProtectedWriteBlocked,
    check_protected_write,
    clear_audit_log,
    get_audit_log,
    is_protected_path,
    register_audit_sink,
)
from carapace.epistemic import (
    GENESIS_HASH,
    ConfidenceLevel,
    EpistemicEntry,
    EpistemicLog,
    Source,
    hash_data,
)
from carapace.compliance import (
    BUILTIN_PROFILES,
    ComplianceProfile,
    ComplianceResult,
    ComplianceViolation,
    evaluate_compliance,
)
from carapace.escalation import (
    INDUSTRIAL_ESCALATION_POLICY,
    EscalationDenied,
    EscalationPolicy,
    EscalationRequest,
    EscalationRequired,
    EscalationStatus,
    EscalationTimedOut,
    EscalationTrigger,
    EscalationUrgency,
    check_all_escalations,
    check_escalation,
)

from carapace.catalog import (
    CatalogEntry,
    CatalogState,
    GateResult,
    fetch_catalog,
    run_gate_check,
)
from carapace.receipt import (
    create_receipt,
    verify_receipt,
    post_receipt,
    post_receipt_async,
)

__version__ = "0.5.0"
