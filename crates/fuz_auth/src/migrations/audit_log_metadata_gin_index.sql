-- audit_log_metadata_gin_index: the GIN the per-cell audit timeline assumes.
--
-- Appended, never folded into `full_auth_schema` — an already-bootstrapped DB
-- has recorded that migration as applied, so an index added there would never
-- land there. See the module doc in `migrations.rs`.
--
-- `full_auth_schema` ships only btree indexes (seq, account, event_type,
-- targets), but `fuz_cell`'s `query_audit_log_list_by_cell` reconstructs the
-- per-cell timeline by OR-ing `metadata @> jsonb_build_object(...)` containment
-- clauses — sequential scans without this index, degrading with audit volume.
--
-- `jsonb_path_ops` rather than the default `jsonb_ops`: it serves exactly the
-- `@>` containment operator these queries use, with a smaller, faster index.
-- pglet parses-and-ignores the opclass (its generic GIN serves the containment);
-- pglite and server PG honor it.

CREATE INDEX IF NOT EXISTS idx_audit_log_metadata ON audit_log USING gin (metadata jsonb_path_ops);
