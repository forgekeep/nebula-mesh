-- Add predecessor_id column to cas table for CA rotation.
-- When a CA is rotated, the new CA row is created with predecessor_id pointing
-- to the old CA's id. The old CA remains active; its signed certs stay valid.
-- This supports the hybrid rotation model: operator receives warning badge
-- (NewCA.ShouldRenew) and can manually trigger rotation via UI/API/CLI.

ALTER TABLE cas ADD COLUMN predecessor_id TEXT REFERENCES cas(id) ON DELETE SET NULL;
CREATE INDEX idx_cas_predecessor ON cas(predecessor_id) WHERE predecessor_id IS NOT NULL;
