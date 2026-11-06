//! HTTP-status classification shared by the HTTP backends (`ForgeStorage`,
//! `HttpsStorage`).
//!
//! Its own module rather than private to one backend, so both land on one
//! mapping rather than each deriving it.

/// `true` for 401/403 (credentials missing/insufficient).
///
/// Used by the HTTP backends so the "auth-status → permission denied" mapping
/// lives in one place.
pub fn is_auth_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN
}

#[cfg(test)]
mod tests {
    use super::is_auth_status;
    use reqwest::StatusCode;

    #[test]
    fn auth_statuses_are_401_and_403_only() {
        // The two auth-failure statuses the HTTP backends map to PermissionDenied.
        assert!(is_auth_status(StatusCode::UNAUTHORIZED)); // 401
        assert!(is_auth_status(StatusCode::FORBIDDEN)); // 403
        // Everything else is a non-auth status the callers handle separately
        // (404 = missing, 429/5xx = transient, 200 = success).
        for status in [
            StatusCode::OK,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_REQUEST,
        ] {
            assert!(!is_auth_status(status), "{status} must not be auth");
        }
    }
}
