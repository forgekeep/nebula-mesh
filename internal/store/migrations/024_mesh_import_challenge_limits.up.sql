CREATE INDEX idx_mesh_import_challenges_active_session
    ON mesh_import_challenges(mesh_import_id, consumed_at, expires_at);

CREATE INDEX idx_mesh_import_challenges_active_fingerprint
    ON mesh_import_challenges(mesh_import_id, certificate_fingerprint, consumed_at, expires_at);
