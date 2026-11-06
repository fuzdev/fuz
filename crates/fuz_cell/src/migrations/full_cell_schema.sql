-- Cell content-primitive schema (no-hub). Mirrors fuz_app's
-- db/cell_ddl.ts. `path` is the sole namespace axis, globally unique on
-- active rows. FKs into `actor` (created by the fuz_auth namespace, which
-- runs first). The full cell-layer surface ships in this one migration,
-- matching the TS twin's schema snapshot.

CREATE TYPE cell_visibility AS ENUM ('private', 'public');

CREATE TABLE cell (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  data        JSONB NOT NULL,
  kind        TEXT,
  visibility  cell_visibility NOT NULL DEFAULT 'private',
  path        TEXT,
  refs        TEXT[],
  parent_id   UUID REFERENCES cell(id) ON DELETE SET NULL,
  root_id     UUID REFERENCES cell(id) ON DELETE SET NULL,
  moderation  TEXT,
  policy      JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ,
  deleted_at  TIMESTAMPTZ,
  created_by  UUID REFERENCES actor(id) ON DELETE SET NULL,
  updated_by  UUID REFERENCES actor(id) ON DELETE SET NULL,
  -- A contribution policy is a root's alone, and always a JSON object
  -- (`@> '{}'` holds for an object and nothing else; the TS twin runs on
  -- pglet, which has no `jsonb_typeof`).
  CHECK (policy IS NULL OR (parent_id IS NULL AND policy @> '{}'::jsonb))
);

CREATE INDEX        idx_cell_active      ON cell(created_at) WHERE deleted_at IS NULL;
CREATE INDEX        idx_cell_kind        ON cell (kind) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_cell_path_unique ON cell(path)       WHERE path IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX        idx_cell_data        ON cell USING gin(data) WHERE deleted_at IS NULL;
CREATE INDEX        idx_cell_refs        ON cell USING gin(refs) WHERE refs IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX        idx_cell_created_by  ON cell(created_by) WHERE deleted_at IS NULL;
-- Directory tree: flat-subtree feed/scope queries by governing root.
CREATE INDEX        idx_cell_root        ON cell(root_id) WHERE deleted_at IS NULL;
-- Moderation queue: pending contributions per governing root.
CREATE INDEX        idx_cell_moderation_pending ON cell(root_id) WHERE moderation = 'pending';

-- Resource-side ACL. Written by the grant verbs (fuz_cell_actions) and read
-- by the view / edit predicates' grant branch (cell_authz).
CREATE TABLE cell_grant (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cell_id     UUID NOT NULL REFERENCES cell(id) ON DELETE CASCADE,
  level       TEXT NOT NULL CHECK (level IN ('viewer', 'editor')),
  actor_id    UUID REFERENCES actor(id) ON DELETE CASCADE,
  role        TEXT,
  scope_id    UUID,
  granted_by  UUID REFERENCES actor(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((actor_id IS NOT NULL AND role IS NULL AND scope_id IS NULL)
      OR (actor_id IS NULL AND role IS NOT NULL))
);
CREATE INDEX        idx_cell_grant_cell             ON cell_grant(cell_id);
CREATE INDEX        idx_cell_grant_actor            ON cell_grant(actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX        idx_cell_grant_role_scope       ON cell_grant(role, scope_id) WHERE role IS NOT NULL;
CREATE UNIQUE INDEX idx_cell_grant_unique_actor     ON cell_grant(cell_id, actor_id) WHERE actor_id IS NOT NULL;
CREATE UNIQUE INDEX idx_cell_grant_unique_role_scope ON cell_grant(cell_id, role, scope_id) NULLS NOT DISTINCT WHERE role IS NOT NULL;

CREATE TABLE cell_field (
  source_id  UUID NOT NULL REFERENCES cell(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  target_id  UUID NOT NULL REFERENCES cell(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (source_id, name)
);
CREATE INDEX idx_cell_field_target ON cell_field(target_id);

CREATE TABLE cell_item (
  parent_id  UUID NOT NULL REFERENCES cell(id) ON DELETE CASCADE,
  position   TEXT NOT NULL,
  child_id   UUID NOT NULL REFERENCES cell(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (parent_id, position)
);
CREATE INDEX idx_cell_item_parent_position ON cell_item(parent_id, position);
CREATE INDEX idx_cell_item_child           ON cell_item(child_id);
