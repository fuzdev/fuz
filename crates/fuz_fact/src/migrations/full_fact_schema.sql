-- fuz_fact: content-addressed byte store (fact + fact_ref + memo).
--
-- Byte-identical to fuz_app's `db/fact_ddl.ts` — the schema-parity gate diffs
-- this against the TS spine. `fact.hash` is the `blake3:<hex64>` content
-- address; bytes XOR external_url per the CHECK. `fact_ref.target_hash` is
-- intentionally NOT a foreign key (a ref may target a fact stored on another
-- instance — federation). `memo` ships DDL-only (no Rust MemoStore yet; matches
-- the TS side).

CREATE TABLE IF NOT EXISTS fact (
	hash TEXT PRIMARY KEY,
	bytes BYTEA,
	external_url TEXT,
	content_type TEXT,
	size BIGINT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT fact_storage_present CHECK (bytes IS NOT NULL OR external_url IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS fact_ref (
	source_hash TEXT NOT NULL REFERENCES fact(hash) ON DELETE CASCADE,
	target_hash TEXT NOT NULL,
	PRIMARY KEY (source_hash, target_hash)
);

CREATE INDEX IF NOT EXISTS idx_fact_ref_target ON fact_ref(target_hash);

CREATE TABLE IF NOT EXISTS memo (
	fn_id TEXT NOT NULL,
	input_hash TEXT NOT NULL,
	output_hash TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (fn_id, input_hash)
);
