-- drop_provenance_stamp_foreign_keys: the stamps that record who did a thing
-- carry no foreign key — `actor.updated_by` / `deleted_by`,
-- `role_grant.granted_by` / `revoked_by`, and `role_grant.source_offer_id`.
--
-- Appended, never folded into `full_auth_schema` or
-- `role_grant_offer_and_scoped_role_grants` — an already-bootstrapped DB has
-- recorded those as applied. See the module doc in `migrations.rs`.
--
-- A stamp is provenance, read by nothing that authorizes, so it keeps the id
-- it was written with after its actor (or offer) is purged, as `audit_log`'s
-- identity columns and `account`'s stamps do. With the foreign key, a purge's
-- cascade wrote other accounts' rows (`ON DELETE SET NULL`) in whatever order
-- its plan walked them, and a write stamping an actor being purged waited on
-- the actor's row while holding the row the cascade needed next: a deadlock.
-- Without it, the cascade never writes a stamp and a stamp write takes no
-- lock on its actor. The references that carry meaning keep theirs: every
-- `actor_id` and `account_id`, an offer's parties, an invite's issuer.
--
-- The constraints carry their default names (`<table>_<column>_fkey`), the
-- same on both spines. `IF EXISTS`, so a re-run is a no-op.

ALTER TABLE actor DROP CONSTRAINT IF EXISTS actor_updated_by_fkey;
ALTER TABLE actor DROP CONSTRAINT IF EXISTS actor_deleted_by_fkey;
ALTER TABLE role_grant DROP CONSTRAINT IF EXISTS role_grant_granted_by_fkey;
ALTER TABLE role_grant DROP CONSTRAINT IF EXISTS role_grant_revoked_by_fkey;
ALTER TABLE role_grant DROP CONSTRAINT IF EXISTS role_grant_source_offer_id_fkey;
