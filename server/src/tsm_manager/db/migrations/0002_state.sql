-- Estado do Manager que o Git não guarda: resultados idempotentes de publicação,
-- auditoria e caches derivados (manifesto por commit, commit materializado no shared).

CREATE TABLE publications (
  idempotency_key TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  result TEXT NOT NULL,
  at TEXT NOT NULL
) STRICT;
CREATE INDEX publications_project ON publications (project_id);

CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  event TEXT NOT NULL,
  project_id TEXT,
  actor_user TEXT,
  actor_device TEXT,
  fields TEXT NOT NULL
) STRICT;
CREATE INDEX audit_logs_project ON audit_logs (project_id, id);

CREATE TABLE revision_manifests (
  project_id TEXT NOT NULL,
  commit_id TEXT NOT NULL,
  files TEXT NOT NULL,
  PRIMARY KEY (project_id, commit_id)
) STRICT;

CREATE TABLE shared_state (
  project_id TEXT PRIMARY KEY,
  commit_id TEXT NOT NULL,
  at TEXT NOT NULL
) STRICT;
