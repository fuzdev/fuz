//! Splitting a stream payload across frames, so no frame exceeds the frame
//! limit.
//!
//! A frame's body is capped at [`FRAME_BODY_BUDGET`], and the connection's
//! writer refuses one over it. A collector's payloads have no bound of their
//! own — a snapshot or a delta grows with the number of processes or
//! connections on the machine, an event batch with how much changed — so every
//! collector frame is encoded through [`split_encode`]: a payload that fits is
//! one body; one that does not is halved and each half encoded again, until
//! each piece fits.
//!
//! The halves of a delta or an event batch, applied one after the other, leave
//! the consumer where the whole would have: a delta's entities are distinct, and
//! events keep their order. A single item that does not fit even alone is
//! dropped and counted in [`SplitBodies::dropped`]; the caller logs it and
//! resyncs, since the consumer would otherwise miss it without a sign.

use fuz_wire::{Action, HEADER_BYTES, MAX_FRAME, ProtoError, encode_payload};

/// The largest body a frame carries: [`MAX_FRAME`] less the header after the
/// length prefix.
pub const FRAME_BODY_BUDGET: usize = (MAX_FRAME - HEADER_BYTES) as usize;

/// The bodies a payload was encoded to, in order, each at most the budget.
#[derive(Debug, Default)]
pub struct SplitBodies {
    pub bodies: Vec<Vec<u8>>,
    /// Pieces that held a single item and still did not fit; they are in no
    /// body.
    pub dropped: usize,
}

/// Encode `payload` into bodies of at most `budget` bytes each.
///
/// `split` halves a payload, or hands it back when it cannot be halved (it
/// holds one item or none). A piece that cannot be halved and does not fit is
/// dropped and counted.
///
/// # Errors
///
/// Returns the [`ProtoError`] of a payload that fails to encode.
pub fn split_encode<P: Action>(
    payload: P,
    budget: usize,
    split: fn(P) -> Result<(P, P), P>,
) -> Result<SplitBodies, ProtoError> {
    let mut out = SplitBodies::default();
    let mut pending = vec![payload];
    // A stack, second half pushed first, so the bodies come out in order.
    while let Some(piece) = pending.pop() {
        let body = encode_payload(&piece)?;
        if body.len() <= budget {
            out.bodies.push(body);
            continue;
        }
        match split(piece) {
            Ok((first, second)) => {
                pending.push(second);
                pending.push(first);
            }
            Err(_) => out.dropped += 1,
        }
    }
    Ok(out)
}

/// Halve a list, or hand it back when it holds one item or none.
///
/// # Errors
///
/// Returns `items` itself when it cannot be halved.
pub fn split_vec<T>(mut items: Vec<T>) -> Result<(Vec<T>, Vec<T>), Vec<T>> {
    if items.len() <= 1 {
        return Err(items);
    }
    let second = items.split_off(items.len() / 2);
    Ok((items, second))
}

/// Three lists, as a delta's `added` / `changed` / `removed` are.
pub type Lists<A, B, C> = (Vec<A>, Vec<B>, Vec<C>);

/// Two halves of [`Lists`], or the whole when it cannot be halved.
pub type ListsSplit<A, B, C> = Result<(Lists<A, B, C>, Lists<A, B, C>), Lists<A, B, C>>;

/// Halve three lists at the midpoint of their combined length, the first half
/// taking from `a`, then `b`, then `c`; or hand them back when together they
/// hold one item or none.
///
/// # Errors
///
/// Returns the lists themselves when they cannot be halved.
pub fn split_lists<A, B, C>((mut a, mut b, mut c): Lists<A, B, C>) -> ListsSplit<A, B, C> {
    let total = a.len() + b.len() + c.len();
    if total <= 1 {
        return Err((a, b, c));
    }
    let mut rest = total / 2;
    let take_a = rest.min(a.len());
    let a2 = a.split_off(take_a);
    rest -= take_a;
    let take_b = rest.min(b.len());
    let b2 = b.split_off(take_b);
    rest -= take_b;
    let c2 = c.split_off(rest);
    Ok(((a, b, c), (a2, b2, c2)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_wire::{WatchEvent, WatchEventKind, WatcherEventFrame, decode_payload};

    fn events(n: usize, path_len: usize) -> WatcherEventFrame {
        WatcherEventFrame {
            events: (0..n)
                .map(|i| WatchEvent {
                    path: format!("{i:06}{}", "x".repeat(path_len)),
                    kind: WatchEventKind::Modified,
                })
                .collect(),
        }
    }

    fn split_events(
        frame: WatcherEventFrame,
    ) -> Result<(WatcherEventFrame, WatcherEventFrame), WatcherEventFrame> {
        split_vec(frame.events)
            .map(|(a, b)| {
                (
                    WatcherEventFrame { events: a },
                    WatcherEventFrame { events: b },
                )
            })
            .map_err(|events| WatcherEventFrame { events })
    }

    #[test]
    fn a_payload_that_fits_is_one_body() {
        let out = split_encode(events(4, 8), 1024, split_events).unwrap();
        assert_eq!(out.bodies.len(), 1);
        assert_eq!(out.dropped, 0);
    }

    #[test]
    fn an_oversize_payload_splits_into_fitting_bodies_in_order() {
        let whole = events(100, 100);
        let budget = 1000;
        assert!(encode_payload(&whole).unwrap().len() > budget);
        let out = split_encode(whole.clone(), budget, split_events).unwrap();
        assert!(out.bodies.len() > 1);
        assert_eq!(out.dropped, 0);
        let mut seen = Vec::new();
        for body in &out.bodies {
            assert!(body.len() <= budget, "every body within the budget");
            let frame: WatcherEventFrame = decode_payload(body).unwrap();
            seen.extend(frame.events.into_iter().map(|e| e.path));
        }
        let expected: Vec<String> = whole.events.into_iter().map(|e| e.path).collect();
        assert_eq!(seen, expected, "every item once, in order");
    }

    #[test]
    fn an_item_too_large_alone_is_dropped_and_counted() {
        let mut frame = events(3, 10);
        frame.events[1].path = "y".repeat(5000);
        let out = split_encode(frame, 1000, split_events).unwrap();
        assert_eq!(out.dropped, 1);
        let kept: usize = out
            .bodies
            .iter()
            .map(|b| decode_payload::<WatcherEventFrame>(b).unwrap().events.len())
            .sum();
        assert_eq!(kept, 2, "the two that fit still go out");
    }

    #[test]
    fn split_lists_halves_across_the_three_lists_in_order() {
        let ((a1, b1, c1), (a2, b2, c2)) =
            split_lists((vec![1, 2], vec![3, 4, 5], vec![6])).unwrap();
        assert_eq!((a1, b1, c1), (vec![1, 2], vec![3], vec![]));
        assert_eq!((a2, b2, c2), (vec![], vec![4, 5], vec![6]));
        let one: Lists<u8, u8, u8> = (vec![], vec![], vec![1]);
        assert!(split_lists(one).is_err(), "one item cannot be halved");
    }
}
