//! Bearer auth helpers.
//!
//! The full bearer pipeline lives in `resolve::resolve_bearer_from_headers`;
//! this module hosts the small browser-context guard so it's testable
//! in isolation and shared with future REST routes.

/// True when the request carries a browser-context header (`Origin` or
/// `Referer`), on which the bearer and daemon-token legs discard their
/// credential — matches `fuz_app`'s `bearer_auth.ts`.
///
/// A defense against a token replayed from a cross-origin page, which sends
/// `Origin`, not a proof that the caller is not a browser: a same-origin `GET`
/// sends no `Origin`, and with `referrerPolicy: 'no-referrer'` no `Referer`
/// either, so page script on the origin keeps a token it attaches. Nothing
/// checks the peer address.
#[must_use]
pub fn is_browser_context(headers: &axum::http::HeaderMap) -> bool {
    headers.contains_key("origin") || headers.contains_key("referer")
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
    use axum::http::header::{ORIGIN, REFERER};

    use super::is_browser_context;

    #[test]
    fn no_browser_headers_is_not_browser_context() {
        assert!(!is_browser_context(&HeaderMap::new()));
    }

    #[test]
    fn origin_marks_browser_context() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, "https://app.example".parse().unwrap());
        assert!(is_browser_context(&headers));
    }

    #[test]
    fn referer_marks_browser_context() {
        let mut headers = HeaderMap::new();
        headers.insert(REFERER, "https://app.example/page".parse().unwrap());
        assert!(is_browser_context(&headers));
    }

    #[test]
    fn both_browser_headers_marks_browser_context() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, "https://app.example".parse().unwrap());
        headers.insert(REFERER, "https://app.example/page".parse().unwrap());
        assert!(is_browser_context(&headers));
    }
}
