CREATE TABLE mesh_imports (
    id                              TEXT PRIMARY KEY,
    network_id                      TEXT NOT NULL REFERENCES networks(id) ON DELETE RESTRICT,
    ca_id                           TEXT NOT NULL REFERENCES cas(id) ON DELETE RESTRICT,
    owner_operator_id               TEXT NOT NULL REFERENCES operators(id) ON DELETE RESTRICT,
    ca_fingerprint                  TEXT NOT NULL,
    status                          TEXT NOT NULL CHECK (status IN ('collecting', 'finalized', 'canceled')),
    expected_hosts                  INTEGER CHECK (expected_hosts IS NULL OR expected_hosts > 0),
    revision                        INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    token_hash                      TEXT NOT NULL UNIQUE,
    token_expires_at                DATETIME NOT NULL,
    captured_network_config_version INTEGER NOT NULL CHECK (captured_network_config_version >= 0),
    terminal_reason                 TEXT NOT NULL DEFAULT '',
    created_at                      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finalized_at                    DATETIME,
    canceled_at                     DATETIME
);

CREATE UNIQUE INDEX ux_mesh_imports_collecting_network
    ON mesh_imports(network_id) WHERE status = 'collecting';
CREATE INDEX idx_mesh_imports_owner ON mesh_imports(owner_operator_id);
CREATE INDEX idx_mesh_imports_ca ON mesh_imports(ca_id);
CREATE INDEX idx_mesh_imports_status ON mesh_imports(status);

CREATE TABLE mesh_import_snapshots (
    id                      TEXT PRIMARY KEY,
    mesh_import_id          TEXT NOT NULL REFERENCES mesh_imports(id) ON DELETE CASCADE,
    host_id                 TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    certificate_fingerprint TEXT NOT NULL,
    certificate_pem         TEXT NOT NULL,
    agent_signing_pub_pem   TEXT NOT NULL,
    payload_hash            TEXT NOT NULL,
    snapshot_json           TEXT NOT NULL,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(mesh_import_id, host_id)
);

CREATE UNIQUE INDEX ux_mesh_import_snapshots_fingerprint
    ON mesh_import_snapshots(certificate_fingerprint);
CREATE INDEX idx_mesh_import_snapshots_session
    ON mesh_import_snapshots(mesh_import_id);

CREATE TABLE host_agent_profiles (
    host_id                TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    mesh_import_id         TEXT REFERENCES mesh_imports(id) ON DELETE SET NULL,
    nebula_config_path     TEXT NOT NULL,
    nebula_ca_path         TEXT NOT NULL,
    nebula_cert_path       TEXT NOT NULL,
    nebula_key_path        TEXT NOT NULL,
    config_ack_v1          BOOLEAN NOT NULL DEFAULT 0,
    pending_config_version INTEGER NOT NULL DEFAULT 0 CHECK (pending_config_version >= 0),
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_host_agent_profiles_session
    ON host_agent_profiles(mesh_import_id);

CREATE TABLE mesh_import_challenges (
    id                      TEXT PRIMARY KEY,
    mesh_import_id          TEXT NOT NULL REFERENCES mesh_imports(id) ON DELETE CASCADE,
    certificate_fingerprint TEXT NOT NULL,
    agent_signing_pub_pem   TEXT NOT NULL,
    payload_hash            TEXT NOT NULL,
    server_nonce            TEXT NOT NULL,
    expires_at              DATETIME NOT NULL,
    consumed_at             DATETIME,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mesh_import_challenges_session
    ON mesh_import_challenges(mesh_import_id);
CREATE INDEX idx_mesh_import_challenges_expiry
    ON mesh_import_challenges(expires_at);

CREATE TABLE mesh_import_tombstones (
    certificate_fingerprint TEXT PRIMARY KEY,
    former_host_id          TEXT NOT NULL,
    mesh_import_id          TEXT NOT NULL REFERENCES mesh_imports(id) ON DELETE CASCADE,
    agent_signing_pub_pem   TEXT NOT NULL,
    terminal_reason         TEXT NOT NULL,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mesh_import_tombstones_session
    ON mesh_import_tombstones(mesh_import_id);
