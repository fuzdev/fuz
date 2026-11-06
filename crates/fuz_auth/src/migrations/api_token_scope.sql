-- api_token_scope: per-credential authority narrowing on API tokens.
--
-- Appended, never folded into `full_auth_schema` — an already-bootstrapped DB
-- has recorded that migration as applied, so a column added there would never
-- land there. See the module doc in `migrations.rs`.
--
-- Three statements, and the middle one is the whole compatibility story:
--
-- 1. Add the column nullable, so the ALTER is instant on a populated table.
-- 2. Backfill every pre-existing token as full authority, flagged
--    `grandfathered` — tokens minted before scoping existed keep working
--    (the only known bearer automation is fuzf against a deployed forge), but
--    the debt is a *value in the row*, not an absence. That distinction is the
--    point: `grandfathered: true` stays distinguishable from a deliberately
--    minted full token, so the token list can label it and an operator can
--    count what still needs re-minting.
-- 3. `SET NOT NULL`, which is what makes "unscoped" unrepresentable from here
--    on. A missing scope is exactly the permissive default this refuses; after
--    this statement the database cannot hold one.
--
-- The backfilled literal is pinned by `token_scope::tests::
-- grandfathered_backfill_parses_and_denotes_full` — `TokenScopeDocument::parse`
-- is fail-closed, so a drift between this literal and the parser stops every
-- pre-scoping token loudly rather than silently widening it.

ALTER TABLE api_token ADD COLUMN IF NOT EXISTS scope JSONB;

UPDATE api_token
   SET scope = '{"version":1,"kind":"full","grandfathered":true}'::jsonb
 WHERE scope IS NULL;

ALTER TABLE api_token ALTER COLUMN scope SET NOT NULL;
