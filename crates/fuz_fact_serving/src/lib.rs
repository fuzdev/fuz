//! `fuz_fact_serving` — the cell-gated reader-facade over `fuz_fact`.
//!
//! The serving half of the fact layer and the **sole authz'd reader** of fact
//! bytes. It composes `fuz_cell::can_view_cell` + the `cell.refs ∋ hash` edge
//! check (it does not reimplement authz) to gate two axum routes that twin
//! `fuz_app`'s `serve_fact_route.ts`:
//!
//! - [`cell_fact_router`] — `GET /api/cells/{cell_id}/facts/{hash}`, the
//!   per-reference public read (authz on the cell→fact edge).
//! - [`bare_fact_router`] — `GET /api/facts/{hash}`, admin-only.
//! - [`fact_routers`] — both (the default mount).
//!
//! `fuz_fact` itself has no HTTP / cell / authz dep (a gated layering rule), so
//! bytes can only reach a client through this crate.
//!
//! [`XAccelConfig`] is the make-impossible-states gate for the X-Accel serving
//! path: a public facts location bypasses every cell check, so the redirect
//! prefix can only be obtained by passing the nginx config through
//! [`validate_facts_internal_location`] (which [`XAccelConfig::new`] runs),
//! making the fail-loud `internal;` assertion structural rather than a step a
//! consumer must remember. On that path nginx serves the bytes with the facts
//! location's own headers, so the validator also requires the lines
//! [`fact_security_header_directives`] renders from [`FACT_SECURITY_HEADERS`].

pub mod fact_security_headers;
pub mod nginx;
pub mod serve;

pub use fact_security_headers::{
    FACT_CONTENT_SECURITY_POLICY, FACT_SECURITY_HEADERS, FACT_X_CONTENT_TYPE_OPTIONS,
    fact_security_header_directives,
};
pub use nginx::{
    NginxFactsValidation, XAccelConfig, XAccelConfigError, validate_facts_internal_location,
};
pub use serve::{FactServingRouteState, bare_fact_router, cell_fact_router, fact_routers};
