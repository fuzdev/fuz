-- fuz_auth migration v1: role_grant_offer + scoped role_grants.
-- Twins fuz_app's `role_grant_offer_and_scoped_role_grants` entry in
-- src/lib/auth/migrations.ts, composed from:
--   - role_grant_offer_ddl.ts (ROLE_GRANT_OFFER_SCHEMA, pending unique index, inbox index)
--   - the inline ALTERs + index swap inside the migration body
--
-- Hardcoded constants (kept literal so each .sql file is self-contained):
--   ROLE_GRANT_OFFER_SCOPE_KIND_GLOBAL_TOKEN = 'GLOBAL'
--   ROLE_GRANT_OFFER_SCOPE_SENTINEL_UUID    = '00000000-0000-0000-0000-000000000000'

CREATE TABLE IF NOT EXISTS role_grant_offer (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  from_actor_id UUID NOT NULL REFERENCES actor(id) ON DELETE CASCADE,
  to_account_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  to_actor_id UUID NULL REFERENCES actor(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  scope_kind TEXT NULL,
  scope_id UUID NULL,
  message TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ NULL,
  declined_at TIMESTAMPTZ NULL,
  decline_reason TEXT NULL,
  retracted_at TIMESTAMPTZ NULL,
  superseded_at TIMESTAMPTZ NULL,
  resulting_role_grant_id UUID NULL REFERENCES role_grant(id) ON DELETE SET NULL,
  CONSTRAINT role_grant_offer_single_terminal CHECK (
    (accepted_at IS NOT NULL)::int
    + (declined_at IS NOT NULL)::int
    + (retracted_at IS NOT NULL)::int
    + (superseded_at IS NOT NULL)::int
    <= 1
  ),
  CONSTRAINT role_grant_offer_role_grant_iff_accepted CHECK (
    (accepted_at IS NOT NULL) = (resulting_role_grant_id IS NOT NULL)
  ),
  CONSTRAINT role_grant_offer_reason_iff_declined CHECK (
    decline_reason IS NULL OR declined_at IS NOT NULL
  ),
  CONSTRAINT role_grant_offer_scope_kind_paired CHECK (
    (scope_kind IS NULL) = (scope_id IS NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS role_grant_offer_pending_unique
  ON role_grant_offer (
    to_account_id,
    role,
    COALESCE(scope_kind, 'GLOBAL'),
    COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid),
    from_actor_id
  )
  WHERE accepted_at IS NULL
    AND declined_at IS NULL
    AND retracted_at IS NULL
    AND superseded_at IS NULL;

CREATE INDEX IF NOT EXISTS role_grant_offer_inbox
  ON role_grant_offer (to_account_id, expires_at)
  WHERE accepted_at IS NULL
    AND declined_at IS NULL
    AND retracted_at IS NULL
    AND superseded_at IS NULL;

ALTER TABLE role_grant ADD COLUMN IF NOT EXISTS scope_id UUID NULL;
ALTER TABLE role_grant ADD COLUMN IF NOT EXISTS scope_kind TEXT NULL;
ALTER TABLE role_grant ADD COLUMN IF NOT EXISTS source_offer_id UUID NULL
  REFERENCES role_grant_offer(id) ON DELETE SET NULL;
ALTER TABLE role_grant ADD COLUMN IF NOT EXISTS revoked_reason TEXT NULL;

-- Paired-null CHECK on (scope_kind, scope_id) — both null encodes global,
-- both non-null encodes a scoped grant. Idempotent across re-applies via a DO
-- block that adds the constraint and swallows duplicate_object (Postgres has no
-- ADD CONSTRAINT IF NOT EXISTS for CHECK). Unlike a host-language try/catch —
-- which aborts the chain transaction once the error reaches the driver — a
-- PL/pgSQL EXCEPTION block handles the duplicate inside a subtransaction, so the
-- outer migration transaction survives. Backend-portable: server PG, PGlite, and
-- pglet all run this form. (This flat-SQL migration can't use the imperative
-- information_schema look-before-leap fuz_app's TS migration uses — pglet has no
-- pg_constraint catalog nor PL/pgSQL IF/THEN, but its minimal DO block does
-- support the EXCEPTION idiom, matching the cell layer's idempotent CREATE TYPE.)
DO $$ BEGIN
  ALTER TABLE role_grant
    ADD CONSTRAINT role_grant_scope_kind_paired
    CHECK ((scope_kind IS NULL) = (scope_id IS NULL));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Swap the (actor_id, role) partial unique for the scope-aware variant.
-- Existing rows have scope_id = NULL (and scope_kind = NULL per the pair
-- invariant) and collapse to the index-side 'GLOBAL' token + all-zeros
-- sentinel UUID.
DROP INDEX IF EXISTS role_grant_actor_role_active_unique;
DROP INDEX IF EXISTS role_grant_actor_role_scope_active_unique;

CREATE UNIQUE INDEX IF NOT EXISTS role_grant_actor_role_scope_active_unique
  ON role_grant (
    actor_id,
    role,
    COALESCE(scope_kind, 'GLOBAL'),
    COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid)
  )
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS role_grant_scope_active
  ON role_grant (actor_id, role, scope_id)
  WHERE revoked_at IS NULL;
