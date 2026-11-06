//! Global app settings row.

/// Single-row settings table — `id = 1` enforced by `CHECK` constraint.
/// Mirrors `fuz_app`'s `AppSettings`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AppSettings {
    pub open_signup: bool,
}
