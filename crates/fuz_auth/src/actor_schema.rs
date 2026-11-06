//! Actor row shape.

/// Row from the `actor` table.
#[derive(Debug, Clone)]
pub struct ActorRow {
    pub id: uuid::Uuid,
    pub account_id: uuid::Uuid,
    pub name: String,
}
