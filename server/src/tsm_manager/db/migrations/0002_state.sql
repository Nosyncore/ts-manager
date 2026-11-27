-- Estado do Manager que o Git não guarda: resultados idempotentes de publicação,
-- auditoria e caches derivados (manifesto por commit, commit materializado no shared).
-- Tudo com escopo por projeto.

CREATE TABLE publications (
  project_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  result TEXT NOT NULL,
  at TEXT NOT NULL,
  PRIMARY KEY (project_id, idempotency_key)
) STRICT;

-- Auditoria só recebe INSERT: alteração ou remoção de um evento é recusada pelo banco.
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
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'auditoria é append-only'); END;
CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'auditoria é append-only'); END;

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
