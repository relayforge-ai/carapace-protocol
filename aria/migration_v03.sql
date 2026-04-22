-- Carapace v0.3 — ARIA schema migration
-- Adds delegation_tokens table for storing signed delegation chains.

CREATE TABLE IF NOT EXISTS delegation_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegator_card_id UUID NOT NULL REFERENCES agents(id),
    delegator_public_key TEXT NOT NULL,
    delegate_card_id UUID NOT NULL REFERENCES agents(id),
    delegated_capabilities JSONB NOT NULL,  -- sorted string array
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    parent_delegation_id UUID REFERENCES delegation_tokens(id),
    max_redelegation_depth INTEGER NOT NULL DEFAULT 2,
    task_context TEXT,
    nonce TEXT NOT NULL,
    signature TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'  -- active, expired, revoked
);

-- Indexes for common lookup patterns
CREATE INDEX IF NOT EXISTS idx_deleg_delegator ON delegation_tokens(delegator_card_id);
CREATE INDEX IF NOT EXISTS idx_deleg_delegate ON delegation_tokens(delegate_card_id);
CREATE INDEX IF NOT EXISTS idx_deleg_parent ON delegation_tokens(parent_delegation_id);
CREATE INDEX IF NOT EXISTS idx_deleg_expires ON delegation_tokens(expires_at);

-- Optional: run as a cron job to mark expired tokens
-- UPDATE delegation_tokens SET status = 'expired'
-- WHERE expires_at < NOW() AND status = 'active';
