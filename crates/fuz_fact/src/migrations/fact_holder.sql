-- fuz_fact: possession records (fact_holder).
--
-- One row per (actor, fact) the actor has put — identical bytes put again by
-- another actor add that actor's row too (holding the bytes is possession).
-- Cell ref admission reads it: a non-admin write may introduce a `blake3:`
-- ref only for a fact its acting actor holds. Byte-identical to fuz_app's
-- `db/fact_ddl.ts` entry of the same name.
--
-- `actor_id` references the auth schema's `actor` table, so this namespace
-- runs after `fuz_auth`. Both FKs cascade: deleting an actor erases its
-- possession, and deleting a fact (the orphan sweep) drops its holders.
-- `idx_fact_holder_hash` serves the fact-side cascade; the primary key
-- leads with `actor_id`, which serves the admission lookup and the
-- actor-side cascade.

CREATE TABLE IF NOT EXISTS fact_holder (
	actor_id UUID NOT NULL REFERENCES actor(id) ON DELETE CASCADE,
	hash TEXT NOT NULL REFERENCES fact(hash) ON DELETE CASCADE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (actor_id, hash)
);

CREATE INDEX IF NOT EXISTS idx_fact_holder_hash ON fact_holder(hash);
