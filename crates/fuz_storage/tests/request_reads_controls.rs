//! Positive controls for the request-reads census's method disallows (the
//! workspace `clippy.toml`; the census is `fuz_testing`'s,
//! run by `fuz_testing`'s `tests/request_reads_census.rs`). Each uses one
//! disallowed method under an `#[expect]`, fulfilled only while clippy
//! resolves that entry, so a path that stops resolving fails `-D warnings`.
//! They live here because this crate links `url`, which `fuz_testing` does
//! not. One item per method — a shared expectation is fulfilled by any one of
//! them.

#[expect(
    dead_code,
    clippy::disallowed_methods,
    reason = "positive control: unfulfilled once `form_urlencoded::parse` stops resolving"
)]
fn form_urlencoded_parse_control() -> usize {
    url::form_urlencoded::parse(b"").count()
}

#[expect(
    dead_code,
    clippy::disallowed_methods,
    reason = "positive control: unfulfilled once `url::Url::query_pairs` stops resolving"
)]
fn url_query_pairs_control(url: &url::Url) -> usize {
    url.query_pairs().count()
}
