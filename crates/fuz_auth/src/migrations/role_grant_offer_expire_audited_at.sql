-- role_grant_offer_expire_audited_at: the expiry-audit stamp that makes the
-- offer sweep idempotent.
--
-- Appended, never folded into `role_grant_offer_and_scoped_role_grants` — an
-- already-bootstrapped DB has recorded that migration as applied, so a column
-- added there would never land there. See the module doc in `migrations.rs`.
--
-- An expired pending offer has no terminal state — expiry is computed from
-- `expires_at`, never written — so without a stamp every sweep re-audited every
-- expired offer. `cleanup_expired_role_grant_offers` claims rows by setting
-- `expire_audited_at` in the same transaction as their
-- `role_grant_offer_expire` audit rows, so each expiry is audited once and
-- concurrent sweeps claim disjoint rows.
--
-- Not a lifecycle state: the column stays out of the
-- `role_grant_offer_single_terminal` CHECK and the pending predicate, and off
-- the wire. A re-offer of a stamped row clears it (the create upsert), so the
-- refreshed offer's own expiry is audited too. The partial index serves exactly
-- the sweep's claim predicate. No backfill: an offer that expired before this
-- migration is audited on the first sweep after it.

ALTER TABLE role_grant_offer ADD COLUMN IF NOT EXISTS expire_audited_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS role_grant_offer_expire_sweep
  ON role_grant_offer (expires_at)
  WHERE accepted_at IS NULL
    AND declined_at IS NULL
    AND retracted_at IS NULL
    AND superseded_at IS NULL
    AND expire_audited_at IS NULL;
