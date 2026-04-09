-- Carapace v0.2 — ARIA schema migration
-- Adds expires_at, card_version, supersedes, superseded_by to the agents table.

ALTER TABLE agents
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS card_version INTEGER DEFAULT 1,
  ADD COLUMN IF NOT EXISTS supersedes UUID DEFAULT NULL REFERENCES agents(id),
  ADD COLUMN IF NOT EXISTS superseded_by UUID DEFAULT NULL;

-- Indexes for version history queries
CREATE INDEX IF NOT EXISTS idx_agents_supersedes ON agents(supersedes);
CREATE INDEX IF NOT EXISTS idx_agents_superseded_by ON agents(superseded_by);
