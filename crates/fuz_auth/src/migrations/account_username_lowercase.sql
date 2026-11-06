-- account_username_lowercase: every `account.username` lowercase.
--
-- Appended, never folded into `full_auth_schema` — an already-bootstrapped DB
-- has recorded that migration as applied. See the module doc in
-- `migrations.rs`.
--
-- `canonical_username_for_creation` lowercases every name production creates,
-- so the wire's username is the stored one and the case-insensitive unique
-- index reads the same value as the column.
--
-- `ADD CONSTRAINT … CHECK` validates the rows already there: a database
-- holding a username with an uppercase letter (one written outside the
-- creation paths, by hand or by a harness) fails the migration on
-- `check_violation`, and the chain's transaction rolls back. Lowercase those
-- rows (`UPDATE account SET username = lower(username)`, which the unique index
-- on `LOWER(username)` keeps from colliding) and migrate again. Idempotent via
-- the `duplicate_object` handler, as `role_grant_scope_kind_paired`.

DO $$ BEGIN
  ALTER TABLE account
    ADD CONSTRAINT account_username_lowercase
    CHECK (username = lower(username));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
