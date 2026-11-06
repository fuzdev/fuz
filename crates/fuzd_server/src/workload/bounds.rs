//! Bounds on the text an observer reports about other processes and the system.
//!
//! Every string a collector forwards was chosen by someone else: a process's
//! name and command line (any local user's), a unit's name and description, an
//! interface name, an address. None has a bound of its own that the wire can
//! rely on — `/proc/<pid>/cmdline` is as long as the argument vector, and an
//! [`ObserverSource`](super::source::ObserverSource) other than the shipped one
//! reports whatever it read. So each is cut to a fixed length before it reaches
//! a frame: at the read where the read can stop early (the command line), and
//! again in the collector, so the bound holds whatever the source.
//!
//! A cut value ends in [`CUT_MARKER`] and is at most its bound in bytes, the
//! marker included; the cut falls on a character boundary. A value at or under
//! its bound passes unchanged.

/// The most bytes a process's command line is reported with.
pub const MAX_CMDLINE_BYTES: usize = 4096;

/// The most bytes a unit's description is reported with.
pub const MAX_DESCRIPTION_BYTES: usize = 1024;

/// The most bytes any other reported string is reported with: a process name,
/// a unit name or state, an interface name, an address. Each of these is short
/// on a real system (a kernel `comm` is 15 bytes, a unit name at most 255, an
/// interface name 15), so this bound only ever cuts a value no real system
/// produces.
pub const MAX_FIELD_BYTES: usize = 256;

/// What a cut value ends in.
pub const CUT_MARKER: &str = "...";

/// Cut `text` to at most `max` bytes, ending in [`CUT_MARKER`], if it is longer.
pub fn cap_text(text: &mut String, max: usize) {
    if text.len() > max {
        cut_text(text, max);
    }
}

/// Cut `text` to at most `max` bytes ending in [`CUT_MARKER`], whatever its
/// length — for a value whose read already stopped short of the whole.
pub fn cut_text(text: &mut String, max: usize) {
    let mut end = max.saturating_sub(CUT_MARKER.len()).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(CUT_MARKER);
}

/// [`cap_text`] on an optional value.
pub fn cap_opt_text(text: &mut Option<String>, max: usize) {
    if let Some(text) = text {
        cap_text(text, max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_within_its_bound_is_unchanged() {
        let mut text = "a".repeat(16);
        cap_text(&mut text, 16);
        assert_eq!(text, "a".repeat(16));
    }

    #[test]
    fn a_long_value_is_cut_to_its_bound_with_the_marker() {
        let mut text = "a".repeat(17);
        cap_text(&mut text, 16);
        assert_eq!(text.len(), 16);
        assert_eq!(text, format!("{}{CUT_MARKER}", "a".repeat(13)));
    }

    #[test]
    fn the_cut_falls_on_a_character_boundary() {
        // `é` is two bytes; a cut at 13 would split the seventh one.
        let mut text = "é".repeat(20);
        cap_text(&mut text, 16);
        assert!(text.len() <= 16, "{text:?}");
        assert!(text.ends_with(CUT_MARKER));
        assert_eq!(text, format!("{}{CUT_MARKER}", "é".repeat(6)));
    }

    #[test]
    fn a_read_that_stopped_short_is_marked_even_when_it_fits() {
        let mut text = "abc".to_string();
        cut_text(&mut text, 16);
        assert_eq!(text, format!("abc{CUT_MARKER}"));
    }
}
