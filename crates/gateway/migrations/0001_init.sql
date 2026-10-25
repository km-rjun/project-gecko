-- Schema v1. Specification: docs/02-security-and-vault-spec.md §4.
-- Conventions: UUIDv7 TEXT ids, Unix-millisecond INTEGER timestamps, 0/1 booleans.

CREATE TABLE users (
  id                  TEXT PRIMARY KEY,
  username            TEXT NOT NULL UNIQUE COLLATE NOCASE,
  is_admin            INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0,1)),
  disabled            INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
  kdf_alg             TEXT NOT NULL CHECK (kdf_alg = 'argon2id-v19'),
  kdf_m_kib           INTEGER NOT NULL,
  kdf_t               INTEGER NOT NULL,
  kdf_p               INTEGER NOT NULL,
  kdf_salt            BLOB NOT NULL CHECK (length(kdf_salt) = 16),
  auth_verifier       BLOB NOT NULL CHECK (length(auth_verifier) = 32),
  mvk_nonce           BLOB NOT NULL CHECK (length(mvk_nonce) = 24),
  mvk_wrapped         BLOB NOT NULL CHECK (length(mvk_wrapped) = 48),
  rk_salt             BLOB NOT NULL CHECK (length(rk_salt) = 16),
  mvk_rk_nonce        BLOB NOT NULL CHECK (length(mvk_rk_nonce) = 24),
  mvk_rk_wrapped      BLOB NOT NULL CHECK (length(mvk_rk_wrapped) = 48),
  crypto_version      INTEGER NOT NULL DEFAULT 1,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL,
  password_changed_at INTEGER NOT NULL
);

CREATE TABLE auth_sessions (
  token_hash    BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  ip            TEXT NOT NULL,
  user_agent    TEXT NOT NULL
);
CREATE INDEX auth_sessions_user ON auth_sessions(user_id);

CREATE TABLE invites (
  id          TEXT PRIMARY KEY,
  token_hash  BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  used_by     TEXT REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE edge_pools (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);

CREATE TABLE edge_pool_grants (
  pool_id  TEXT NOT NULL REFERENCES edge_pools(id) ON DELETE CASCADE,
  user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (pool_id, user_id)
);

CREATE TABLE edge_runners (
  id               TEXT PRIMARY KEY,
  pool_id          TEXT NOT NULL REFERENCES edge_pools(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  cert_serial      BLOB NOT NULL UNIQUE,
  cert_spki_sha256 BLOB NOT NULL CHECK (length(cert_spki_sha256) = 32),
  cert_not_after   INTEGER NOT NULL,
  prev_cert_serial BLOB,
  prev_valid_until INTEGER,
  status           TEXT NOT NULL CHECK (status IN ('active','revoked')),
  last_seen_at     INTEGER,
  last_remote_addr TEXT,
  version          TEXT,
  created_at       INTEGER NOT NULL
);

CREATE TABLE runner_enrollment_tokens (
  id             TEXT PRIMARY KEY,
  token_hash     BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  pool_id        TEXT NOT NULL REFERENCES edge_pools(id) ON DELETE CASCADE,
  created_by     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  used_at        INTEGER,
  used_by_runner TEXT REFERENCES edge_runners(id) ON DELETE SET NULL
);

CREATE TABLE nodes (
  id                    TEXT PRIMARY KEY,
  owner_user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team_vault_id         TEXT CHECK (team_vault_id IS NULL),
  meta_aead             TEXT NOT NULL CHECK (meta_aead = 'xchacha20poly1305-v1'),
  meta_nonce            BLOB NOT NULL CHECK (length(meta_nonce) = 24),
  meta_ciphertext       BLOB NOT NULL CHECK (length(meta_ciphertext) % 256 = 16),
  ephemeral_auth        INTEGER NOT NULL DEFAULT 0 CHECK (ephemeral_auth IN (0,1)),
  edge_pool_id          TEXT REFERENCES edge_pools(id) ON DELETE RESTRICT,
  edge_runner_pin       TEXT REFERENCES edge_runners(id) ON DELETE SET NULL,
  allow_clipboard_copy  INTEGER NOT NULL DEFAULT 1 CHECK (allow_clipboard_copy IN (0,1)),
  allow_clipboard_paste INTEGER NOT NULL DEFAULT 1 CHECK (allow_clipboard_paste IN (0,1)),
  allow_file_transfer   INTEGER NOT NULL DEFAULT 0 CHECK (allow_file_transfer IN (0,1)),
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER NOT NULL,
  CHECK (edge_runner_pin IS NULL OR edge_pool_id IS NOT NULL)
);
CREATE INDEX nodes_owner ON nodes(owner_user_id);

CREATE TABLE encrypted_secrets (
  node_id        TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  owner_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  aead           TEXT NOT NULL CHECK (aead = 'xchacha20poly1305-v1'),
  nonce          BLOB NOT NULL CHECK (length(nonce) = 24),
  ciphertext     BLOB NOT NULL CHECK (length(ciphertext) % 512 = 16),
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

-- Ephemeral nodes can never hold secrets, enforced in the database as well as in code.
CREATE TRIGGER encrypted_secrets_no_ephemeral
BEFORE INSERT ON encrypted_secrets
WHEN (SELECT ephemeral_auth FROM nodes WHERE id = NEW.node_id) = 1
BEGIN SELECT RAISE(ABORT, 'ephemeral node cannot store secrets'); END;

CREATE TRIGGER encrypted_secrets_no_ephemeral_update
BEFORE UPDATE ON encrypted_secrets
WHEN (SELECT ephemeral_auth FROM nodes WHERE id = NEW.node_id) = 1
BEGIN SELECT RAISE(ABORT, 'ephemeral node cannot store secrets'); END;

CREATE TRIGGER nodes_ephemeral_purge
AFTER UPDATE OF ephemeral_auth ON nodes
WHEN NEW.ephemeral_auth = 1
BEGIN DELETE FROM encrypted_secrets WHERE node_id = NEW.id; END;

CREATE TABLE node_host_identities (
  node_id        TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  owner_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  aead           TEXT NOT NULL CHECK (aead = 'xchacha20poly1305-v1'),
  nonce          BLOB NOT NULL CHECK (length(nonce) = 24),
  ciphertext     BLOB NOT NULL CHECK (length(ciphertext) >= 16),
  approved_at    INTEGER NOT NULL
);

CREATE TABLE audit_logs (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id        TEXT NOT NULL UNIQUE,
  ts              INTEGER NOT NULL,
  actor_user_id   TEXT,
  actor_runner_id TEXT,
  source_ip       TEXT,
  event           TEXT NOT NULL,
  node_id         TEXT,
  outcome         TEXT NOT NULL CHECK (outcome IN ('success','failure','denied')),
  details         TEXT NOT NULL DEFAULT '{}',
  sealed_nonce    BLOB CHECK (sealed_nonce IS NULL OR length(sealed_nonce) = 24),
  sealed_details  BLOB,
  prev_hash       BLOB NOT NULL CHECK (length(prev_hash) = 32),
  entry_hash      BLOB NOT NULL CHECK (length(entry_hash) = 32)
);
CREATE INDEX audit_logs_actor ON audit_logs(actor_user_id, seq);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
