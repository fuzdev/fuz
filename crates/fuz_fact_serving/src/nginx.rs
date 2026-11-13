//! Fail-loud validation of the X-Accel facts nginx location.
//!
//! The `X-Accel-Redirect` serving path's confidentiality depends on the facts
//! nginx location being `internal;` — only the authz'd handler's redirect (an
//! internal subrequest) may reach it. A *public* facts location would serve
//! any fact's bytes to anyone who guesses the `<shard>/<rest>` path, bypassing
//! every cell-visibility check. A location with its own `add_header` also
//! stops the server-level headers from applying, so the facts location must
//! carry the fact hardening headers itself
//! ([`fact_security_header_directives`]).
//!
//! [`XAccelConfig`] makes these assertions structural: a consumer can only
//! obtain the redirect prefix by building an `XAccelConfig`, which runs
//! [`validate_facts_internal_location`] and fails **loudly** (a `Result` error)
//! on any violation — it cannot silently fall closed.
//!
//! ```
//! use fuz_fact_serving::XAccelConfig;
//!
//! let nginx = r#"server {
//!     listen 443 ssl;
//!     location ^~ /_facts/ {
//!         internal;
//!         alias /srv/app/facts/;
//!         add_header X-Content-Type-Options "nosniff" always;
//!         add_header Content-Security-Policy "default-src 'none'; sandbox" always;
//!     }
//! }"#;
//! let x_accel = XAccelConfig::new("/_facts/", nginx).expect("a safe facts location");
//! assert_eq!(x_accel.redirect_prefix(), "/_facts/");
//! ```
//!
//! ## Rules
//!
//! The config is tokenized as nginx reads it (`ngx_conf_read_token`):
//! whitespace is exactly space, tab, CR and LF; an unquoted word ends only at
//! those or at `;` / `{` (a `}` inside a word is part of it, and so is a `{`
//! straight after `$`); `#` starts a comment only where a token would start;
//! quoted strings are one word, with nginx's backslash escapes. It is then
//! parsed into nested blocks, and every `location` at any depth, in every
//! `server` block, is classified against the prefix (trailing slashes
//! ignored). A location *serves the prefix* when it is a prefix-type location
//! (no modifier, or `^~`) whose path is the prefix or below it. Each one must:
//!
//! - use `^~` — a plain prefix location is refused;
//! - be a direct child of a `server` block — one nested in another location
//!   is refused;
//! - carry, as top-level directives of its own body, an exact `internal;` and
//!   each [`fact_security_header_directives`] line (token-equal: whitespace
//!   and quoting are free, the words are not);
//! - set those headers with no other `add_header` — one naming a
//!   [`FACT_SECURITY_HEADERS`] header (ASCII case-insensitive) that is not
//!   token-equal to its required line is refused, since nginx sends both
//!   values and a client may read only the first (`sniff, nosniff`);
//! - hold only simple directives — any nested block (`location`, `if`,
//!   `limit_except`, …) is refused, and so is `include`, since included files
//!   are not followed.
//!
//! The first two rules are what keep regex locations out: nginx never
//! evaluates regex locations for a path whose longest prefix match is a `^~`
//! location at server level, and because every prefix location at or below
//! the prefix must be such a location, the longest match for any redirected
//! path always is. (A longer plain location below the prefix can't exist —
//! the `^~` rule refuses it.)
//!
//! The prefix may appear only in its own location lines and their bodies:
//! `internal;` admits every internal redirect and subrequest, so any other
//! directive with a word naming the prefix (trailing slash trimmed, so
//! `/_facts$uri` counts) is refused, in any block at any depth — a `rewrite`,
//! `try_files`, `error_page`, `index`, `add_before_body`, or a `set` / `map`
//! value that a redirect later reads. The only exemptions are each
//! `location`'s own modifier and path words and the bodies of the locations
//! serving the prefix.
//!
//! The prefix itself must be an absolute path ending in exactly one `/` — the
//! server appends `<shard>/<rest>` straight onto it, so `/_facts` would
//! redirect to `/_factsab/…`, outside the validated location. At least one
//! location serving the prefix must sit exactly at it (`/_facts` or
//! `/_facts/`): one only below it (`location ^~ /_facts/00/`) leaves every
//! other redirect path to whatever location matches next, and nginx compares
//! location paths byte-for-byte, so `/_facts//` sits below it too.
//!
//! Module directives that undo those guarantees are refused too:
//!
//! - `ssi` with any value but `off`, anywhere in the config. SSI `include
//!   virtual` is a subrequest, which `internal;` admits, so an SSI-processed
//!   response — a fact inheriting `ssi on` from `http` or `server`, or any
//!   page carrying user content — could include another fact's bytes.
//! - `more_set_headers` / `more_clear_headers` (headers-more) everywhere
//!   except inside a `location` that doesn't serve the prefix (or a block
//!   within one): they run after `add_header` and can strip the hardening
//!   headers, so they are refused in the facts location and at every level
//!   above it, including any block there (`if`, another `server`).
//!
//! Also refused: an `=` location on the prefix or below it (it can't serve the
//! nested paths the redirect emits); a regex location (`~` / `~*`) whose
//! pattern spells out the prefix (after unescaping `\/`, ASCII case-folded for
//! `~*`) — dead under the rules above, refused for the clearer message; a
//! config with no location at the prefix; and blocks nested more than 64 deep
//! (a parse error, so the walks can't exhaust the stack). `include` at server
//! level is allowed, but its file is not read — keep facts-related locations
//! and the directives above out of included files.
//!
//! The threat model is operator mistakes, not an adversarial config author:
//! the prefix check is textual, so a value assembled from pieces (`/_fac$1`)
//! evades it. Beyond the config text:
//!
//! - The validator checks URL paths only — another `root` or `alias` that maps
//!   onto the facts directory would serve its files publicly, so keep the facts
//!   directory outside every other location's root.
//! - nginx honours `X-Accel-Redirect` from any proxied upstream (`proxy_pass`,
//!   `fastcgi_pass`, `uwsgi_pass`, `scgi_pass`, `grpc_pass`), so every upstream
//!   in the server is trusted to point into the prefix; an untrusted one needs
//!   `proxy_ignore_headers X-Accel-Redirect;` (or the `fastcgi_` / `uwsgi_` /
//!   `scgi_` equivalent).
//! - Other module code can redirect internally too (njs `internalRedirect`,
//!   perl, echo), or strip the hardening headers as headers-more can (njs
//!   `js_header_filter`, lua-nginx-module `header_filter_by_lua*`), and the
//!   check sees none of it, so run trusted modules and content only.
//!
//! The TS twin is `fuz_app`'s `server/x_accel.ts`, held to the same rules and
//! the same fixture corpus.

use crate::fact_security_headers::{FACT_SECURITY_HEADERS, fact_security_header_directives};

/// Result of the facts-location check.
#[derive(Debug, Clone)]
pub struct NginxFactsValidation {
    /// `true` when every rule passes.
    pub ok: bool,
    /// Fatal issues, each naming the offending location.
    pub errors: Vec<String>,
}

/// Assert the nginx config serves the X-Accel facts prefix only from
/// `internal;` locations carrying the fact hardening headers.
///
/// `facts_location` is the path the X-Accel redirect prefix points at (e.g.
/// `/_facts/`). See the module docs for the rules; every violation is
/// collected, so one call reports them all.
#[must_use]
pub fn validate_facts_internal_location(
    config: &str,
    facts_location: &str,
) -> NginxFactsValidation {
    let errors = match collect_errors(config, facts_location) {
        Ok(errors) => errors,
        Err(parse_error) => vec![format!(
            "could not parse the nginx config ({parse_error}) — the X-Accel facts location \
             can't be verified `internal;`.",
        )],
    };
    NginxFactsValidation {
        ok: errors.is_empty(),
        errors,
    }
}

fn collect_errors(config: &str, facts_location: &str) -> Result<Vec<String>, String> {
    let prefix = facts_location.trim_end_matches('/');
    if !facts_location.starts_with('/') || prefix.is_empty() {
        return Ok(vec![format!(
            "X-Accel redirect prefix `{facts_location}` must be an absolute path below `/` \
             (e.g. `/_facts/`).",
        )]);
    }
    if facts_location.len() != prefix.len() + 1 {
        return Ok(vec![format!(
            "X-Accel redirect prefix `{facts_location}` must end in exactly one `/` (e.g. \
             `/_facts/`) — the server appends `<shard>/<rest>` straight onto it, so any other \
             ending redirects outside the validated location.",
        )]);
    }
    let directives = parse_directives(&tokenize(config)?)?;
    let mut locations = Vec::new();
    collect_locations(&directives, None, &mut locations)?;

    let required: Vec<[&str; 4]> = FACT_SECURITY_HEADERS
        .iter()
        .map(|(name, value)| ["add_header", name, value, "always"])
        .collect();
    let rendered = fact_security_header_directives();

    let mut errors = Vec::new();
    let mut at_prefix = false;
    for location in &locations {
        let label = location.label();
        match location.modifier {
            LocationModifier::Named => {}
            LocationModifier::Prefix | LocationModifier::PrefixNoRegex => {
                if !path_is_under(&location.path, prefix) {
                    continue;
                }
                // nginx compares location paths byte-for-byte, so `/_facts//` never
                // matches `/_facts/ab/…` — only `/_facts` and `/_facts/` sit at the prefix
                if matches!(location.path.strip_prefix(prefix), Some("" | "/")) {
                    at_prefix = true;
                }
                if location.modifier != LocationModifier::PrefixNoRegex {
                    errors.push(format!(
                        "{label} must use `^~` (`location ^~ {}`) — on a plain prefix location \
                         nginx goes on to check regex locations, any of which can serve fact \
                         bytes publicly.",
                        location.path,
                    ));
                }
                if location.parent.as_deref() != Some("server") {
                    errors.push(format!(
                        "{label} must be a direct child of a `server` block — inside another \
                         block, `^~` doesn't stop nginx checking regex locations.",
                    ));
                }
                if !has_directive(location.body, &["internal"]) {
                    errors.push(format!(
                        "{label} is NOT marked `internal;` — a public facts location serves any \
                         fact's bytes to anyone who guesses the path, bypassing every \
                         cell-visibility check. Add `internal;` as a directive of the block itself.",
                    ));
                }
                for (args, line) in required.iter().zip(&rendered) {
                    if !has_directive(location.body, args) {
                        errors.push(format!(
                            "{label} lacks `{line}` — a location's own `add_header` replaces the \
                             server-level headers, so without it fact bytes go out without that \
                             hardening header.",
                        ));
                    }
                }
                for directive in location.body {
                    let name = directive.args.first().map_or("", String::as_str);
                    if directive.block.is_none()
                        && name == "add_header"
                        && let Some(header) = directive.args.get(1)
                        && let Some(index) =
                            FACT_SECURITY_HEADERS.iter().position(|(required_name, _)| {
                                required_name.eq_ignore_ascii_case(header)
                            })
                        && directive.args != required[index]
                    {
                        errors.push(format!(
                            "{label} has another `add_header {header}` (line {}) — nginx sends every \
                             `add_header` for a header and a client may read only the first, so the \
                             facts location may set `{}` only with `{}`.",
                            directive.line, FACT_SECURITY_HEADERS[index].0, rendered[index],
                        ));
                    }
                    if directive.block.is_some() {
                        errors.push(format!(
                            "{label} contains a nested `{name}` block (line {}) — the facts \
                             location must hold only simple directives, since a nested block can \
                             serve or re-header the bytes.",
                            directive.line,
                        ));
                    } else if name == "include" {
                        errors.push(format!(
                            "{label} contains `include` (line {}) — included files are not \
                             followed, so the facts location can't contain one.",
                            directive.line,
                        ));
                    }
                }
            }
            LocationModifier::Exact => {
                if path_is_under(&location.path, prefix) {
                    errors.push(format!(
                        "{label} is an exact-match location on the facts prefix — it can't serve \
                         the nested `<shard>/<rest>` paths the redirect emits, and one below the \
                         prefix shadows the internal location. Use a `^~` location.",
                    ));
                }
            }
            LocationModifier::Regex | LocationModifier::RegexCaseless => {
                let pattern = location.path.replace("\\/", "/");
                let shadows = if location.modifier == LocationModifier::RegexCaseless {
                    pattern
                        .to_ascii_lowercase()
                        .contains(&prefix.to_ascii_lowercase())
                } else {
                    pattern.contains(prefix)
                };
                if shadows {
                    errors.push(format!(
                        "{label} is a regex location naming the facts prefix — remove it; the \
                         facts location must be a server-level `^~` location, which nginx \
                         serves without checking regex locations.",
                    ));
                }
            }
        }
    }
    collect_prefix_mention_errors(&directives, prefix, &mut errors);
    collect_module_errors(&directives, prefix, true, &mut errors);
    if !at_prefix {
        errors.insert(
            0,
            format!(
                "No nginx `location ^~ {facts_location}` block found — the X-Accel facts \
                 location must exist exactly at the prefix (one only below it leaves the other \
                 redirect paths uncovered) and be marked `internal;` so only the authz'd \
                 handler's redirect can reach it. A public facts location bypasses every \
                 cell-visibility check.",
            ),
        );
    }
    Ok(errors)
}

/// A validated X-Accel redirect configuration — the only handle that enables
/// the `X-Accel-Redirect` serving path.
///
/// The redirect prefix can be obtained **only** by passing the nginx config
/// through [`validate_facts_internal_location`], so X-Accel serving is
/// impossible to enable without proving at boot that the facts location is
/// `internal;` and carries the fact hardening headers — a public facts
/// location would bypass every cell-visibility check. The fail-loud assertion
/// is thus *structural* (an unconstructable state), not a discipline a
/// consumer has to remember.
#[derive(Debug, Clone)]
pub struct XAccelConfig {
    redirect_prefix: String,
}

impl XAccelConfig {
    /// Build a validated X-Accel config, asserting the nginx config serves
    /// `redirect_prefix` only from safe locations (the module-level rules).
    ///
    /// # Errors
    /// Returns [`XAccelConfigError`] (a fail-loud boot error) carrying every
    /// violation [`validate_facts_internal_location`] finds — a prefix not
    /// ending in `/`, a missing, public, header-less, re-headered, exact-match,
    /// or regex-shadowed facts location, or `ssi` / headers-more reaching it.
    pub fn new(
        redirect_prefix: impl Into<String>,
        nginx_config: &str,
    ) -> Result<Self, XAccelConfigError> {
        let redirect_prefix = redirect_prefix.into();
        let validation = validate_facts_internal_location(nginx_config, &redirect_prefix);
        if !validation.ok {
            return Err(XAccelConfigError {
                errors: validation.errors,
            });
        }
        Ok(Self { redirect_prefix })
    }

    /// The validated redirect prefix the serving path prepends (e.g. `/_facts/`).
    #[must_use]
    pub fn redirect_prefix(&self) -> &str {
        &self.redirect_prefix
    }
}

/// A misconfigured X-Accel facts location — a fail-loud boot error.
#[derive(Debug, thiserror::Error)]
#[error("X-Accel facts location is not safely `internal;`: {}", .errors.join("; "))]
pub struct XAccelConfigError {
    errors: Vec<String>,
}

impl XAccelConfigError {
    /// The validator errors that made the location unsafe.
    #[must_use]
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

/// `true` when `path` is `prefix` or below it, trailing slashes ignored.
fn path_is_under(path: &str, prefix: &str) -> bool {
    let path = path.trim_end_matches('/');
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// `true` when `body` has a top-level simple directive whose words are
/// exactly `args` (a block directive with those words doesn't count).
fn has_directive(body: &[Directive], args: &[&str]) -> bool {
    body.iter()
        .any(|d| d.block.is_none() && d.args.iter().map(String::as_str).eq(args.iter().copied()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocationModifier {
    Prefix,
    PrefixNoRegex,
    Exact,
    Regex,
    RegexCaseless,
    Named,
}

impl LocationModifier {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prefix | Self::Named => "",
            Self::PrefixNoRegex => "^~ ",
            Self::Exact => "= ",
            Self::Regex => "~ ",
            Self::RegexCaseless => "~* ",
        }
    }
}

#[derive(Debug)]
struct Location<'a> {
    modifier: LocationModifier,
    path: String,
    line: usize,
    /// The first word of the enclosing block directive (`server`, `location`,
    /// …), `None` at the top level.
    parent: Option<String>,
    body: &'a [Directive],
}

impl Location<'_> {
    fn label(&self) -> String {
        format!(
            "`location {}{}` (line {})",
            self.modifier.as_str(),
            self.path,
            self.line
        )
    }
}

/// The modifiers nginx accepts glued to the path (`=/x`), longest first so
/// `^~` / `~*` aren't read as `~`.
const GLUED_MODIFIERS: [(&str, LocationModifier); 4] = [
    ("^~", LocationModifier::PrefixNoRegex),
    ("~*", LocationModifier::RegexCaseless),
    ("~", LocationModifier::Regex),
    ("=", LocationModifier::Exact),
];

/// Classify a `location`'s arguments (after the keyword) — the separate
/// (`= /x`) and glued (`=/x`) modifier forms nginx accepts.
fn parse_location_args(args: &[String]) -> Option<(LocationModifier, String)> {
    match args {
        [modifier, path] => {
            let modifier = match modifier.as_str() {
                "=" => LocationModifier::Exact,
                "^~" => LocationModifier::PrefixNoRegex,
                "~" => LocationModifier::Regex,
                "~*" => LocationModifier::RegexCaseless,
                _ => return None,
            };
            Some((modifier, path.clone()))
        }
        [glued] => {
            if glued.starts_with('@') {
                return Some((LocationModifier::Named, glued.clone()));
            }
            for (text, modifier) in GLUED_MODIFIERS {
                if let Some(rest) = glued.strip_prefix(text) {
                    return Some((modifier, rest.to_owned()));
                }
            }
            Some((LocationModifier::Prefix, glued.clone()))
        }
        _ => None,
    }
}

/// Refuse every directive, in any block at any depth, with a word containing
/// the prefix (trailing slash trimmed, so `/_facts$uri` counts) — the prefix
/// may appear only in its own location lines and their bodies. Exempt: each
/// `location` directive's own modifier and path words, and the bodies of the
/// locations serving the prefix (held to simple directives elsewhere). A
/// textual heuristic against operator mistakes: a value assembled from pieces
/// (`/_fac$1`) is not caught.
fn collect_prefix_mention_errors(directives: &[Directive], prefix: &str, errors: &mut Vec<String>) {
    for directive in directives {
        let name = directive.args.first().map_or("", String::as_str);
        if name == "location" {
            let serves_prefix =
                parse_location_args(&directive.args[1..]).is_some_and(|(modifier, path)| {
                    matches!(
                        modifier,
                        LocationModifier::Prefix | LocationModifier::PrefixNoRegex
                    ) && path_is_under(&path, prefix)
                });
            if let Some(block) = &directive.block
                && !serves_prefix
            {
                collect_prefix_mention_errors(block, prefix, errors);
            }
            continue;
        }
        if directive.args.iter().any(|word| word.contains(prefix)) {
            errors.push(format!(
                "`{name}` (line {}) names the facts prefix — the prefix may appear only in its \
                 own location lines and their bodies; anything else naming it (a redirect, a \
                 subrequest, a variable that becomes one) can serve fact bytes publicly.",
                directive.line,
            ));
        }
        if let Some(block) = &directive.block {
            collect_prefix_mention_errors(block, prefix, errors);
        }
    }
}

/// The headers-more module's response-header directives, which run after
/// `add_header` and so can strip or rewrite the fact hardening headers.
const HEADERS_MORE_DIRECTIVES: [&str; 2] = ["more_set_headers", "more_clear_headers"];

/// Refuse the module directives that undo the facts location's guarantees:
///
/// - `ssi` with any value but `off`, in any block at any depth. SSI `include
///   virtual` is a subrequest, which `internal;` admits, so an SSI-processed
///   response — a fact served from the facts location (inheriting `ssi on`
///   from `http` or `server`), or any page carrying user content — could
///   include another fact's bytes by its path. A sibling location's `ssi on`
///   is as dangerous as an inherited one, so the rule is config-wide.
/// - a headers-more directive anywhere except inside a `location` that
///   doesn't serve the prefix (or a block within one): in the facts location's
///   body, or at any level above it (`http`, `server`, top level, and any
///   block there such as `if` or another `server`).
///
/// `reaches_facts` is `true` while the walk is in a scope the facts location
/// inherits from or is.
fn collect_module_errors(
    directives: &[Directive],
    prefix: &str,
    reaches_facts: bool,
    errors: &mut Vec<String>,
) {
    for directive in directives {
        let name = directive.args.first().map_or("", String::as_str);
        if directive.block.is_none() {
            if name == "ssi"
                && !matches!(directive.args.as_slice(), [_, value] if value.eq_ignore_ascii_case("off"))
            {
                errors.push(format!(
                    "`ssi` (line {}) is not `off` — SSI `include virtual` subrequests reach the \
                     `internal;` facts location, so an SSI-processed response could include any \
                     fact's bytes by its path. Remove it or set `ssi off;`.",
                    directive.line,
                ));
            } else if reaches_facts && HEADERS_MORE_DIRECTIVES.contains(&name) {
                errors.push(format!(
                    "`{name}` (line {}) applies to the facts location — a headers-more directive \
                     in or above it can strip or rewrite the fact hardening headers after \
                     `add_header` sets them. Move it into the locations that need it.",
                    directive.line,
                ));
            }
        }
        if let Some(block) = &directive.block {
            let reaches = if name == "location" {
                parse_location_args(&directive.args[1..]).is_some_and(|(modifier, path)| {
                    matches!(
                        modifier,
                        LocationModifier::Prefix | LocationModifier::PrefixNoRegex
                    ) && path_is_under(&path, prefix)
                })
            } else {
                reaches_facts
            };
            collect_module_errors(block, prefix, reaches, errors);
        }
    }
}

/// Gather every `location` block at any depth, in document order, each with
/// the name of the block directly enclosing it.
fn collect_locations<'a>(
    directives: &'a [Directive],
    parent: Option<&str>,
    out: &mut Vec<Location<'a>>,
) -> Result<(), String> {
    for directive in directives {
        let Some(block) = &directive.block else {
            continue;
        };
        let name = directive.args.first().map_or("", String::as_str);
        if name == "location" {
            let args = &directive.args[1..];
            let (modifier, path) = parse_location_args(args).ok_or_else(|| {
                format!(
                    "unrecognised `location {}` (line {})",
                    args.join(" "),
                    directive.line
                )
            })?;
            out.push(Location {
                modifier,
                path,
                line: directive.line,
                parent: parent.map(str::to_owned),
                body: block,
            });
        }
        collect_locations(block, Some(name), out)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Semicolon,
    Open,
    Close,
}

#[derive(Debug)]
struct Lexed {
    token: Token,
    line: usize,
}

/// nginx's config whitespace — exactly these four, nothing Unicode.
const fn is_nginx_space(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n')
}

/// Apply nginx's word unescaping: `\"` `\'` `\\` drop the backslash, `\t`
/// `\r` `\n` become the control character, any other backslash stays.
fn unescape_word(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let replacement = match chars.peek() {
                Some(&next @ ('"' | '\'' | '\\')) => Some(next),
                Some('t') => Some('\t'),
                Some('r') => Some('\r'),
                Some('n') => Some('\n'),
                _ => None,
            };
            if let Some(replacement) = replacement {
                chars.next();
                out.push(replacement);
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// Tokenize as nginx's `ngx_conf_read_token` reads a config — the same state
/// machine (`last_space`, `need_space`, `quoted`, `variable`, the quote and
/// comment flags), producing words and the `;` `{` `}` punctuation.
fn tokenize(config: &str) -> Result<Vec<Lexed>, String> {
    let mut tokens = Vec::new();
    let mut line = 1usize;
    let mut start_line = 1usize;
    let mut word = String::new();
    let mut last_space = true;
    let mut need_space = false;
    let mut quoted = false;
    let mut s_quoted = false;
    let mut d_quoted = false;
    let mut sharp_comment = false;
    let mut variable = false;
    for ch in config.chars() {
        if ch == '\n' {
            line += 1;
            sharp_comment = false;
        }
        if sharp_comment {
            continue;
        }
        if quoted {
            quoted = false;
            word.push(ch);
            continue;
        }
        if need_space {
            if is_nginx_space(ch) {
                last_space = true;
                need_space = false;
                continue;
            }
            match ch {
                ';' | '{' => {
                    need_space = false;
                    last_space = true;
                    let token = if ch == ';' {
                        Token::Semicolon
                    } else {
                        Token::Open
                    };
                    tokens.push(Lexed { token, line });
                    continue;
                }
                ')' => {
                    last_space = true;
                    need_space = false;
                }
                _ => {
                    return Err(format!(
                        "unexpected `{ch}` after a quoted string, line {line}"
                    ));
                }
            }
        }
        if last_space {
            start_line = line;
            if is_nginx_space(ch) {
                continue;
            }
            match ch {
                ';' => tokens.push(Lexed {
                    token: Token::Semicolon,
                    line,
                }),
                '{' => tokens.push(Lexed {
                    token: Token::Open,
                    line,
                }),
                '}' => tokens.push(Lexed {
                    token: Token::Close,
                    line,
                }),
                '#' => sharp_comment = true,
                '"' => {
                    d_quoted = true;
                    last_space = false;
                }
                '\'' => {
                    s_quoted = true;
                    last_space = false;
                }
                _ => {
                    if ch == '\\' {
                        quoted = true;
                    } else if ch == '$' {
                        variable = true;
                    }
                    last_space = false;
                    word.push(ch);
                }
            }
            continue;
        }
        if ch == '{' && variable {
            word.push(ch);
            continue;
        }
        variable = false;
        if ch == '\\' {
            quoted = true;
            word.push(ch);
            continue;
        }
        if ch == '$' {
            variable = true;
            word.push(ch);
            continue;
        }
        let found = if d_quoted {
            let closes = ch == '"';
            if closes {
                d_quoted = false;
                need_space = true;
            }
            closes
        } else if s_quoted {
            let closes = ch == '\'';
            if closes {
                s_quoted = false;
                need_space = true;
            }
            closes
        } else if is_nginx_space(ch) || ch == ';' || ch == '{' {
            last_space = true;
            true
        } else {
            false
        };
        if !found {
            word.push(ch);
            continue;
        }
        tokens.push(Lexed {
            token: Token::Word(unescape_word(&word)),
            line: start_line,
        });
        word.clear();
        if ch == ';' || ch == '{' {
            let token = if ch == ';' {
                Token::Semicolon
            } else {
                Token::Open
            };
            tokens.push(Lexed { token, line });
        }
    }
    if !last_space {
        return Err(format!("unexpected end of file inside a word, line {line}"));
    }
    Ok(tokens)
}

/// One parsed directive: its words, the line it starts on, and its block body
/// when it opens one (`server { … }`, `location … { … }`).
#[derive(Debug)]
struct Directive {
    args: Vec<String>,
    line: usize,
    block: Option<Vec<Self>>,
}

/// The deepest block nesting the parser accepts — far beyond any real config,
/// and low enough that the recursive walks can't exhaust the stack.
const MAX_NESTING_DEPTH: usize = 64;

fn parse_directives(tokens: &[Lexed]) -> Result<Vec<Directive>, String> {
    let mut pos = 0;
    parse_block(tokens, &mut pos, None, 0)
}

/// Parse one block's directives; `depth` is the number of blocks enclosing
/// them (`0` at the top level).
fn parse_block(
    tokens: &[Lexed],
    pos: &mut usize,
    open_line: Option<usize>,
    depth: usize,
) -> Result<Vec<Directive>, String> {
    let mut out = Vec::new();
    loop {
        let Some(lexed) = tokens.get(*pos) else {
            return open_line.map_or(Ok(out), |line| {
                Err(format!("unclosed `{{` opened on line {line}"))
            });
        };
        match &lexed.token {
            Token::Close => {
                if open_line.is_none() {
                    return Err(format!("unexpected `}}` on line {}", lexed.line));
                }
                *pos += 1;
                return Ok(out);
            }
            Token::Semicolon => return Err(format!("unexpected `;` on line {}", lexed.line)),
            Token::Open => return Err(format!("unexpected `{{` on line {}", lexed.line)),
            Token::Word(_) => {
                let line = lexed.line;
                let mut args = Vec::new();
                loop {
                    match tokens.get(*pos) {
                        Some(Lexed {
                            token: Token::Word(word),
                            ..
                        }) => {
                            args.push(word.clone());
                            *pos += 1;
                        }
                        Some(Lexed {
                            token: Token::Semicolon,
                            ..
                        }) => {
                            *pos += 1;
                            out.push(Directive {
                                args,
                                line,
                                block: None,
                            });
                            break;
                        }
                        Some(Lexed {
                            token: Token::Open,
                            line: open,
                        }) => {
                            let open = *open;
                            if depth >= MAX_NESTING_DEPTH {
                                return Err(format!(
                                    "blocks nested deeper than {MAX_NESTING_DEPTH} levels (line \
                                     {open})"
                                ));
                            }
                            *pos += 1;
                            let block = parse_block(tokens, pos, Some(open), depth + 1)?;
                            out.push(Directive {
                                args,
                                line,
                                block: Some(block),
                            });
                            break;
                        }
                        Some(Lexed {
                            token: Token::Close,
                            ..
                        })
                        | None => {
                            return Err(format!(
                                "directive `{}` on line {line} is missing its `;`",
                                args.join(" ")
                            ));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus shared with the TS twin — a byte-identical copy lives at
    /// `src/test/server/x_accel_corpus.json` in `fuz_app`. Change both together.
    const CORPUS: &str = include_str!("../tests/fixtures/x_accel_corpus.json");

    #[test]
    fn corpus_verdicts_match() {
        let corpus: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
        let cases = corpus["cases"].as_array().unwrap();
        assert!(!cases.is_empty());
        let mut failures = Vec::new();
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let config = case["config"].as_str().unwrap();
            let prefix = case["prefix"].as_str().unwrap();
            let expected_ok = case["ok"].as_bool().unwrap();
            let result = validate_facts_internal_location(config, prefix);
            if result.ok != expected_ok {
                failures.push(format!(
                    "{name}: expected ok={expected_ok}, got {:?}",
                    result.errors
                ));
                continue;
            }
            if let Some(needle) = case.get("error").and_then(serde_json::Value::as_str)
                && !result.errors.iter().any(|e| e.contains(needle))
            {
                failures.push(format!(
                    "{name}: no error contains {needle:?}: {:?}",
                    result.errors
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn exported_directives_round_trip() {
        let config = format!(
            "server {{ location ^~ /_facts/ {{ internal; {} }} }}",
            fact_security_header_directives().join(" ")
        );
        let result = validate_facts_internal_location(&config, "/_facts/");
        assert!(result.ok, "{:?}", result.errors);
    }

    #[test]
    fn errors_name_the_location_and_line() {
        let config =
            "server {\n  location ^~ /_facts/ { internal; }\n  location /_facts/ab/ { }\n}";
        let result = validate_facts_internal_location(config, "/_facts/");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.starts_with("`location /_facts/ab/` (line 3) must use `^~`")),
            "{:?}",
            result.errors
        );
    }

    #[test]
    fn tokenizer_follows_nginx() {
        let words = |config: &str| -> Vec<String> {
            tokenize(config)
                .unwrap()
                .into_iter()
                .map(|lexed| match lexed.token {
                    Token::Word(word) => word,
                    Token::Semicolon => ";".to_owned(),
                    Token::Open => "{".to_owned(),
                    Token::Close => "}".to_owned(),
                })
                .collect()
        };
        assert_eq!(words("a}b;"), ["a}b", ";"]);
        assert_eq!(words("x ${y z;"), ["x", "${y", "z", ";"]);
        assert_eq!(words("a\u{a0}#b;"), ["a\u{a0}#b", ";"]);
        assert_eq!(words("a#b c; # d;\ne;"), ["a#b", "c", ";", "e", ";"]);
        assert_eq!(
            words(r#"a "b\"c" 'd\'e' f\\g;"#),
            ["a", "b\"c", "d'e", "f\\g", ";"]
        );
        assert_eq!(words("a\u{c}b;"), ["a\u{c}b", ";"]);
        assert!(tokenize("a \"b\"c;").is_err());
        assert!(tokenize("a b").is_err());
    }

    #[test]
    fn refuses_deep_nesting_without_overflowing() {
        // past the cap the parser stops recursing, so even a huge nesting is a clean refusal
        let depth = 100_000;
        let config = format!("{}{}", "a {".repeat(depth), "}".repeat(depth));
        let result = validate_facts_internal_location(&config, "/_facts/");
        assert!(!result.ok);
        assert!(
            result.errors[0].contains("blocks nested deeper than 64 levels"),
            "{:?}",
            result.errors
        );
    }

    #[test]
    fn rejects_root_prefix() {
        let result = validate_facts_internal_location("server { }", "/");
        assert!(!result.ok);
        assert!(result.errors[0].contains("absolute path below"));
    }

    // -- XAccelConfig --

    const SAFE: &str = "server { location ^~ /_facts/ { internal; \
        add_header X-Content-Type-Options \"nosniff\" always; \
        add_header Content-Security-Policy \"default-src 'none'; sandbox\" always; } }";

    #[test]
    fn x_accel_config_requires_a_safe_location() {
        let x_accel = XAccelConfig::new("/_facts/", SAFE).expect("safe location");
        assert_eq!(x_accel.redirect_prefix(), "/_facts/");
    }

    #[test]
    fn x_accel_config_rejects_public_location() {
        // a public location can't be turned into an XAccelConfig at all
        let config = "server { location ^~ /_facts/ { alias /var/facts/; } }";
        let err = XAccelConfig::new("/_facts/", config).expect_err("public location rejected");
        assert!(err.to_string().contains("internal"));
        assert!(!err.errors().is_empty());
    }

    #[test]
    fn x_accel_config_rejects_missing_location() {
        let config = "server { location /api/ { proxy_pass http://app; } }";
        XAccelConfig::new("/_facts/", config).expect_err("missing location rejected");
    }
}
