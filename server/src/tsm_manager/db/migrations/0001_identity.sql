-- Identidade e acessos: usuários, dispositivos, convites, desafios, sessões, vínculos e
-- operações de provisionamento. Horários em texto UTC de largura fixa.

CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('developer', 'admin')),
  status TEXT NOT NULL CHECK (status IN ('active', 'blocked')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE invites (
  id TEXT PRIMARY KEY,
  code_sha256 TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('new_user', 'new_device', 'bootstrap')),
  role TEXT NOT NULL CHECK (role IN ('developer', 'admin')),
  project_id TEXT NOT NULL,
  user_id TEXT REFERENCES users (id),
  created_by TEXT REFERENCES users (id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  revoked_at TEXT,
  CHECK ((kind = 'new_device') = (user_id IS NOT NULL))
) STRICT;

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users (id),
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN
    ('pending', 'provisioning', 'active', 'rejected', 'revoked', 'expired')),
  ssh_account TEXT UNIQUE,
  invite_id TEXT NOT NULL UNIQUE REFERENCES invites (id),
  created_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT REFERENCES users (id),
  last_error TEXT,
  last_seen_at TEXT
) STRICT;
CREATE INDEX devices_user ON devices (user_id);
CREATE INDEX devices_status ON devices (status);

CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
  fingerprint TEXT NOT NULL,
  public_key TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  CHECK ((purpose = 'register') = (public_key IS NOT NULL))
) STRICT;
CREATE INDEX auth_challenges_expires ON auth_challenges (expires_at);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  token_sha256 TEXT NOT NULL UNIQUE,
  device_id TEXT NOT NULL REFERENCES devices (id),
  scope TEXT NOT NULL CHECK (scope IN ('pending', 'full')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
) STRICT;
CREATE INDEX sessions_device ON sessions (device_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE workspace_bindings (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  device_id TEXT NOT NULL REFERENCES devices (id),
  workspace TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (project_id, device_id),
  UNIQUE (project_id, workspace)
) STRICT;

CREATE TABLE provisioning_ops (
  id INTEGER PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices (id),
  action TEXT NOT NULL CHECK (action IN ('create', 'disable', 'enable', 'delete')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'done', 'failed')),
  error TEXT,
  created_at TEXT NOT NULL,
  finished_at TEXT
) STRICT;
CREATE INDEX provisioning_ops_pending ON provisioning_ops (status) WHERE status = 'pending';
