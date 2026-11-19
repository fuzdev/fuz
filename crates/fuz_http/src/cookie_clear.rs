//! The stack's cookie-clear layer: one `Set-Cookie` added to a response when
//! the request carried a cookie its owner says is dead.
//!
//! This crate knows no cookie. A server hands [`compose_stack`] a
//! [`CookieClearHook`] ([`StackOptions::cookie_clear`]) that reads a request's
//! path and headers and answers the `Set-Cookie` value to clear with, or
//! nothing; `fuz_auth::AuthGate::cookie_clear_hook` is the one that reads the
//! session cookie. The credential walk runs per handler and never holds the
//! response, so the clear is a layer.
//!
//! ## Where it sits
//!
//! Inside the origin check, in every group behind it — the fallback included,
//! so an unrouted path is covered. A request the body cap, the host gate, or
//! the origin check refuses never reaches it and gets no clear, as on the TS
//! twin, whose clear sits behind the same gates.
//!
//! ## What it writes
//!
//! - **Never on a `101`.** An accepted WebSocket upgrade carries no clear.
//! - **Ahead of the handler's own `Set-Cookie` lines.** A login carrying a
//!   stale cookie answers the clear, then the new cookie; a browser applies
//!   them in order, so the reverse would delete the session just minted.
//!
//! [`compose_stack`]: crate::compose_stack
//! [`StackOptions::cookie_clear`]: crate::StackOptions::cookie_clear

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

/// The function a [`CookieClearHook`] holds.
type CookieClearFn = dyn Fn(&str, &HeaderMap) -> Option<HeaderValue> + Send + Sync;

/// Decides, from a request's path and headers, whether its response clears a
/// cookie — and with which `Set-Cookie` value.
///
/// Opaque to this crate: the hook owns which cookie, what makes it dead, and
/// which paths it speaks for. Cloning is an `Arc` bump.
///
/// Its `Debug` prints no state — a hook closes over signing keys.
#[derive(Clone)]
pub struct CookieClearHook(Arc<CookieClearFn>);

impl std::fmt::Debug for CookieClearHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieClearHook").finish_non_exhaustive()
    }
}

impl CookieClearHook {
    /// A hook over `clear_for(path, headers)`: the request's path
    /// (`Uri::path`, as the router reads it) and its headers in; the
    /// `Set-Cookie` value to clear with, or `None` to leave the response as
    /// it is.
    #[must_use]
    pub fn new(
        clear_for: impl Fn(&str, &HeaderMap) -> Option<HeaderValue> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(clear_for))
    }

    /// The `Set-Cookie` value the response to this request clears with, if
    /// any.
    #[must_use]
    pub fn clear_for(&self, path: &str, headers: &HeaderMap) -> Option<HeaderValue> {
        (self.0)(path, headers)
    }
}

/// axum middleware over a [`CookieClearHook`]: asks the hook before the
/// handler runs, and writes its answer onto the response (module doc § What
/// it writes).
pub(crate) async fn cookie_clear_layer(
    State(hook): State<CookieClearHook>,
    req: Request,
    next: Next,
) -> Response {
    let clear = hook.clear_for(req.uri().path(), req.headers());
    let mut response = next.run(req).await;
    if let Some(clear) = clear
        && response.status() != StatusCode::SWITCHING_PROTOCOLS
    {
        prepend_set_cookie(response.headers_mut(), clear);
    }
    response
}

/// Put `value` ahead of every `Set-Cookie` line the response already has.
fn prepend_set_cookie(headers: &mut HeaderMap, value: HeaderValue) {
    let existing: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    headers.insert(SET_COOKIE, value);
    for later in existing {
        headers.append(SET_COOKIE, later);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_cookies(headers: &HeaderMap) -> Vec<&str> {
        headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    #[test]
    fn the_clear_goes_ahead_of_every_existing_set_cookie() {
        let mut headers = HeaderMap::new();
        prepend_set_cookie(&mut headers, HeaderValue::from_static("s=; Max-Age=0"));
        assert_eq!(set_cookies(&headers), ["s=; Max-Age=0"]);

        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_static("s=new"));
        headers.append(SET_COOKIE, HeaderValue::from_static("other=1"));
        headers.append("x-kept", HeaderValue::from_static("1"));
        prepend_set_cookie(&mut headers, HeaderValue::from_static("s=; Max-Age=0"));
        assert_eq!(set_cookies(&headers), ["s=; Max-Age=0", "s=new", "other=1"]);
        assert_eq!(headers.get("x-kept").unwrap(), "1");
    }

    #[test]
    fn debug_prints_no_state() {
        let hook = CookieClearHook::new(|_, _| Some(HeaderValue::from_static("secret=1")));
        assert_eq!(format!("{hook:?}"), "CookieClearHook { .. }");
    }
}
