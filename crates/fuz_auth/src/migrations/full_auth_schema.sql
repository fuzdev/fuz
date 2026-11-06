-- fuz_auth: initial DDL.
-- Mirrors fuz_app's `src/lib/auth/auth_ddl.ts` + `audit_log_ddl.ts`.

-- `deleted_at` is the soft-delete tombstone (delete = soft, purge = hard).
-- Auth resolution treats a non-null `deleted_at` as absent; username/email
-- unique indexes stay unconditional so a soft-deleted identity stays
-- reserved (no reuse).
CREATE TABLE IF NOT EXISTS account (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  email TEXT,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID,
  deleted_at TIMESTAMPTZ,
  deleted_by UUID
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_email
  ON account (LOWER(email)) WHERE email IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_username_ci
  ON account (LOWER(username));

CREATE TABLE IF NOT EXISTS actor (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ,
  updated_by UUID REFERENCES actor(id) ON DELETE SET NULL,
  deleted_at TIMESTAMPTZ,
  deleted_by UUID REFERENCES actor(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_actor_account ON actor(account_id);

-- Functional index on LOWER(actor.name) supporting case-insensitive
-- prefix search by actor_search (LOWER(name) LIKE LOWER(query) || '%').
-- text_pattern_ops keeps the LIKE-prefix pattern index-eligible.
CREATE INDEX IF NOT EXISTS idx_actor_name_lower
  ON actor (LOWER(name) text_pattern_ops);

CREATE TABLE IF NOT EXISTS role_grant (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id UUID NOT NULL REFERENCES actor(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  revoked_by UUID REFERENCES actor(id) ON DELETE SET NULL,
  granted_by UUID REFERENCES actor(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_role_grant_actor ON role_grant(actor_id);
CREATE UNIQUE INDEX IF NOT EXISTS role_grant_actor_role_active_unique
  ON role_grant (actor_id, role) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_session (
  id TEXT PRIMARY KEY,
  account_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_session_account ON auth_session(account_id);
CREATE INDEX IF NOT EXISTS idx_auth_session_expires ON auth_session(expires_at);

CREATE TABLE IF NOT EXISTS bootstrap_lock (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  bootstrapped BOOLEAN NOT NULL DEFAULT false
);

INSERT INTO bootstrap_lock (id, bootstrapped)
  SELECT 1, EXISTS(SELECT 1 FROM account)
  ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS app_settings (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  open_signup BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ,
  updated_by UUID
);

INSERT INTO app_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS api_token (
  id TEXT PRIMARY KEY,
  account_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  last_used_ip TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_token_account ON api_token(account_id);

CREATE TABLE IF NOT EXISTS invite (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT,
  username TEXT,
  claimed_by UUID REFERENCES account(id) ON DELETE SET NULL,
  claimed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES actor(id) ON DELETE SET NULL,
  CONSTRAINT invite_has_identifier CHECK (email IS NOT NULL OR username IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_invite_email_unclaimed
  ON invite (LOWER(email))
  WHERE email IS NOT NULL AND claimed_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_invite_username_unclaimed
  ON invite (LOWER(username))
  WHERE username IS NOT NULL AND claimed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_invite_claimed
  ON invite (claimed_at);

-- audit_log: parallels fuz_app's AUDIT_LOG_SCHEMA from auth/audit_log_ddl.ts.
-- target_actor_id is parallel to target_account_id for actor-grain events;
-- both nullable. The four identity columns are plain UUID with NO FK: an
-- audit log is an append-only historical record, not a live relational
-- entity, and `ON DELETE SET NULL` erased the very attribution the log
-- exists to preserve. With soft-delete as the default the rows stay and the
-- ids JOIN-resolve; on a hard purge the raw id survives instead of nulling,
-- and the purge audit event snapshots the identity into metadata
-- (delete = soft, purge = hard).
CREATE TABLE IF NOT EXISTS audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seq BIGSERIAL NOT NULL,
  event_type TEXT NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'success',
  actor_id UUID,
  account_id UUID,
  target_account_id UUID,
  target_actor_id UUID,
  ip TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_seq ON audit_log(seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_account ON audit_log(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_target_account ON audit_log(target_account_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_target_actor ON audit_log(target_actor_id);
