//! The per-connection outbound queue — byte-budgeted, close on overflow.
//!
//! Every frame the server pushes at a connection outside a request's own
//! response — a broadcast, a `send_to`, a `send_to_account`, a
//! server-initiated request, an audit row on an SSE stream — waits here until
//! the connection's writer takes it. A producer never waits on a recipient
//! (`broadcast` is synchronous and called from anywhere), so the queue is
//! where a client that stopped reading makes the server hold memory.
//! It is bounded by one **byte budget**:
//!
//! - **The charge.** Each waiting frame is charged its payload bytes plus
//!   [`OUTBOUND_FRAME_OVERHEAD_BYTES`]. The payload bytes are the length of
//!   the frame's text in UTF-8 — the bytes that go to the socket, before any
//!   transport framing. Fanned-out frames share one buffer; each recipient's
//!   queue is charged the frame in full without copying it. The fixed part
//!   stands for the queue slot and the allocation's bookkeeping, so frames
//!   with little or no payload cannot grow the queue without limit.
//! - **The rule.** A frame is queued when the charges already waiting plus
//!   its own stay within the queue's budget — and, whatever its size, when
//!   the queue is **empty**, so a single message larger than the whole
//!   budget is deliverable.
//!
//! Nothing counts frames: any number of them may wait while their charges
//! fit. A producer that queues a long burst in one go — a loop with no await
//! in it, which leaves the writer no chance to take a frame — is held to the
//! budget alone.
//!
//! A push that does not fit **overflows** the queue: it reports
//! [`Push::Overflow`] once, discards everything queued, and refuses every
//! later push. Nothing is dropped silently — the owner closes the connection
//! on that report — and nothing blocks. A frame the writer has taken is no
//! longer charged, so the budget bounds what is waiting, not what is in
//! flight to the socket (that is the writer's own deadline to bound).
//!
//! ## Halves
//!
//! [`outbound_queue`] returns the queue's two ends, and the sender hands out
//! the pushing handle a fan-out sends through:
//!
//! - [`QueueSender`] — the **owner**, held by the registry entry. Dropping it
//!   closes the queue and wakes the writer; that drop is how every
//!   registry-side close reaches the writer. Not `Clone`, so the close
//!   happens exactly when the entry goes.
//! - [`QueueHandle`] — a pushing handle cloned out of the sender for a
//!   fan-out that sends outside the registry lock. It does not keep the queue
//!   open: a push after the close is refused.
//! - [`QueueReceiver`] — the writer's half. Dropping it discards the queue
//!   and refuses every later push.
//!
//! What a close does to the frames already queued is the queue's
//! [`OnClose`]: a WebSocket discards them, so a close frame never waits
//! behind a backlog; an SSE stream drains them, then ends.

use std::collections::VecDeque;
use std::sync::Arc;

use axum::extract::ws::Utf8Bytes;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::sync::mpsc::error::TryRecvError;

/// What a waiting frame is charged against its queue's byte budget on top of
/// its payload bytes.
///
/// It stands for what a queued frame costs beyond its text: the queue's slot
/// for it and the bookkeeping of the allocation behind it. Without it a
/// frame with an empty payload would be free, and a producer of empty or
/// tiny frames could grow a queue without limit under any byte budget. With
/// it a queue of budget `B` never holds more than `B` divided by this many
/// frames (or one frame, where that is zero), whatever their size.
///
/// The value is a fixed charge, not a measurement of this implementation's
/// memory use.
pub const OUTBOUND_FRAME_OVERHEAD_BYTES: usize = 64;

/// A frame an outbound queue can hold.
pub trait QueuedFrame {
    /// The frame's payload length in bytes — the UTF-8 length of its text.
    /// The queue charges it, plus [`OUTBOUND_FRAME_OVERHEAD_BYTES`], against
    /// the byte budget.
    fn queued_bytes(&self) -> usize;
}

/// What `frames` waiting frames carrying `payload_bytes` between them are
/// charged against a budget; `None` past `usize::MAX`.
const fn charge(payload_bytes: usize, frames: usize) -> Option<usize> {
    match frames.checked_mul(OUTBOUND_FRAME_OVERHEAD_BYTES) {
        Some(overhead) => payload_bytes.checked_add(overhead),
        None => None,
    }
}

impl QueuedFrame for Utf8Bytes {
    fn queued_bytes(&self) -> usize {
        self.as_str().len()
    }
}

impl QueuedFrame for Arc<str> {
    fn queued_bytes(&self) -> usize {
        self.len()
    }
}

/// What closing a queue does to the frames still waiting in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnClose {
    /// Drop them: the receiver reads the close at once.
    Discard,
    /// Keep them: the receiver takes what was queued, then reads the close.
    Drain,
}

/// The outcome of one [`QueueHandle::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// The frame is queued.
    Queued,
    /// The frame was not queued: the queue is closed, has overflowed, or its
    /// receiver is gone.
    Refused,
    /// The frame did not fit. Reported once per queue — the queue has
    /// discarded what it held and refuses every later push; the caller closes
    /// the connection.
    Overflow(Overflow),
}

/// What a queue held when a push overflowed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow {
    /// Payload bytes waiting in the queue, before the discard — without the
    /// per-frame overhead the budget also charges.
    pub queued_bytes: usize,
    /// Frames waiting in the queue, before the discard.
    pub queued_frames: usize,
    /// Payload bytes of the frame that did not fit, without its overhead.
    pub frame_bytes: usize,
}

#[derive(Debug)]
struct State<T> {
    frames: VecDeque<T>,
    /// Sum of the queued frames' payload lengths.
    bytes: usize,
    /// The owner is gone — no frame will ever be queued again.
    closed: bool,
    /// A push overflowed — the queue is empty and refusing, awaiting the
    /// owner's close.
    overflowed: bool,
    /// The receiver is gone — nothing would ever take a frame.
    receiver_gone: bool,
}

#[derive(Debug)]
struct Shared<T> {
    state: Mutex<State<T>>,
    /// Wakes the receiver: a permit per push and per close, so a wake that
    /// lands between the receiver's check and its wait is not lost.
    wake: Notify,
    max_bytes: usize,
    on_close: OnClose,
}

impl<T> Shared<T> {
    /// Empty the queue under its lock and hand the frames back, so the
    /// caller drops them after releasing it.
    fn take_frames(state: &mut State<T>) -> VecDeque<T> {
        state.bytes = 0;
        std::mem::take(&mut state.frames)
    }
}

/// Build a queue with a budget of `max_bytes` (module doc): each waiting
/// frame is charged its payload bytes plus
/// [`OUTBOUND_FRAME_OVERHEAD_BYTES`], and a frame is always queued into an
/// empty queue.
pub fn outbound_queue<T: QueuedFrame>(
    max_bytes: usize,
    on_close: OnClose,
) -> (QueueSender<T>, QueueReceiver<T>) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            frames: VecDeque::new(),
            bytes: 0,
            closed: false,
            overflowed: false,
            receiver_gone: false,
        }),
        wake: Notify::new(),
        max_bytes,
        on_close,
    });
    (
        QueueSender {
            handle: QueueHandle {
                shared: Arc::clone(&shared),
            },
        },
        QueueReceiver { shared },
    )
}

/// The owning half of an outbound queue — dropping it closes the queue
/// (module doc, "Halves").
#[derive(Debug)]
pub struct QueueSender<T> {
    handle: QueueHandle<T>,
}

impl<T> QueueSender<T> {
    /// A pushing handle for a fan-out that sends outside the registry lock.
    pub fn handle(&self) -> QueueHandle<T> {
        self.handle.clone()
    }
}

impl<T> Drop for QueueSender<T> {
    fn drop(&mut self) {
        let shared = &self.handle.shared;
        let discarded = {
            let mut state = shared.state.lock();
            state.closed = true;
            match shared.on_close {
                OnClose::Discard => Shared::take_frames(&mut state),
                OnClose::Drain => VecDeque::new(),
            }
        };
        drop(discarded);
        shared.wake.notify_one();
    }
}

/// A pushing handle to an outbound queue. It does not keep the queue open.
#[derive(Debug)]
pub struct QueueHandle<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for QueueHandle<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T: QueuedFrame> QueueHandle<T> {
    /// Queue `frame`, or report why it was not queued. Never waits.
    ///
    /// A frame fits when the queue is empty, or when the charge of the
    /// waiting frames with it among them stays within the byte budget.
    pub fn push(&self, frame: T) -> Push {
        let frame_bytes = frame.queued_bytes();
        let shared = &self.shared;
        let (outcome, discarded) = {
            let mut state = shared.state.lock();
            if state.closed || state.overflowed || state.receiver_gone {
                return Push::Refused;
            }
            let fits = state.frames.is_empty()
                || state
                    .bytes
                    .checked_add(frame_bytes)
                    .and_then(|payload_bytes| charge(payload_bytes, state.frames.len() + 1))
                    .is_some_and(|charged| charged <= shared.max_bytes);
            if fits {
                state.bytes += frame_bytes;
                state.frames.push_back(frame);
                (Push::Queued, VecDeque::new())
            } else {
                let overflow = Overflow {
                    queued_bytes: state.bytes,
                    queued_frames: state.frames.len(),
                    frame_bytes,
                };
                state.overflowed = true;
                (Push::Overflow(overflow), Shared::take_frames(&mut state))
            }
        };
        drop(discarded);
        if outcome == Push::Queued {
            shared.wake.notify_one();
        }
        outcome
    }
}

/// The writer's half of an outbound queue.
#[derive(Debug)]
pub struct QueueReceiver<T> {
    shared: Arc<Shared<T>>,
}

impl<T: QueuedFrame> QueueReceiver<T> {
    /// Take the next frame under the lock, or say why there is none.
    fn take(&self) -> Result<T, TryRecvError> {
        let mut state = self.shared.state.lock();
        if let Some(frame) = state.frames.pop_front() {
            state.bytes -= frame.queued_bytes();
            return Ok(frame);
        }
        if state.closed {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    /// The next frame, waiting for one; `None` once the queue is closed and
    /// has nothing left to hand out. Cancel-safe: a dropped call takes
    /// nothing. One caller at a time — the queue has a single writer, and a
    /// wake reaches one waiter.
    pub async fn recv(&self) -> Option<T> {
        loop {
            match self.take() {
                Ok(frame) => return Some(frame),
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => self.shared.wake.notified().await,
            }
        }
    }

    /// The next frame if one is queued, without waiting.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.take()
    }

    /// Frames waiting in the queue.
    pub fn len(&self) -> usize {
        self.shared.state.lock().frames.len()
    }

    /// Payload bytes waiting in the queue, without the per-frame overhead
    /// the budget also charges.
    pub fn queued_bytes(&self) -> usize {
        self.shared.state.lock().bytes
    }

    /// Whether the owner has closed the queue.
    pub fn is_closed(&self) -> bool {
        self.shared.state.lock().closed
    }
}

impl<T> Drop for QueueReceiver<T> {
    fn drop(&mut self) {
        let discarded = {
            let mut state = self.shared.state.lock();
            state.receiver_gone = true;
            Shared::take_frames(&mut state)
        };
        drop(discarded);
    }
}

#[cfg(test)]
mod tests {
    //! Pins the queue's bound in isolation: the byte budget is exact and
    //! charges every frame its overhead, nothing else limits how many frames
    //! wait, an oversized frame is deliverable only into an empty queue, an
    //! overflow discards and refuses, and a close discards or drains as the
    //! queue was built.

    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "tests panic on assertion failure by design"
    )]

    use std::sync::Arc;

    use futures::FutureExt;
    use tokio::sync::mpsc::error::TryRecvError;

    use super::{OUTBOUND_FRAME_OVERHEAD_BYTES, OnClose, Overflow, Push, outbound_queue};

    fn frame(bytes: usize) -> Arc<str> {
        Arc::from("x".repeat(bytes))
    }

    /// The charge is part of the contract a port has to match.
    #[test]
    fn the_overhead_is_64_bytes() {
        assert_eq!(OUTBOUND_FRAME_OVERHEAD_BYTES, 64);
    }

    /// Frames charged exactly the budget — payload plus one overhead each —
    /// are queued; one byte more overflows, reporting what was queued.
    #[test]
    fn the_byte_budget_is_exact() {
        let budget = 10 + 2 * OUTBOUND_FRAME_OVERHEAD_BYTES;
        let (tx, rx) = outbound_queue::<Arc<str>>(budget, OnClose::Discard);
        let handle = tx.handle();
        assert_eq!(handle.push(frame(4)), Push::Queued);
        assert_eq!(handle.push(frame(6)), Push::Queued);
        assert_eq!(rx.queued_bytes(), 10, "exactly at the budget");

        assert_eq!(
            handle.push(frame(0)),
            Push::Overflow(Overflow {
                queued_bytes: 10,
                queued_frames: 2,
                frame_bytes: 0,
            }),
            "an empty frame still costs its overhead"
        );
        assert_eq!(rx.queued_bytes(), 0, "the backlog is discarded");
        assert_eq!(rx.len(), 0);
        assert_eq!(handle.push(frame(1)), Push::Refused, "and nothing follows");

        // one byte less of budget and the second frame is the one too many
        let (tx, _rx) = outbound_queue::<Arc<str>>(budget - 1, OnClose::Discard);
        let handle = tx.handle();
        assert_eq!(handle.push(frame(4)), Push::Queued);
        assert!(matches!(handle.push(frame(6)), Push::Overflow(_)));
    }

    /// Tiny frames overflow exactly where `N × (len + 64)` crosses the
    /// budget: the overhead is charged per frame, not once.
    #[test]
    fn each_frame_is_charged_its_overhead() {
        const LEN: usize = 1;
        const FIT: usize = 15;
        let per_frame = LEN + OUTBOUND_FRAME_OVERHEAD_BYTES;
        // room for FIT frames and all but one byte of another
        let budget = (FIT + 1) * per_frame - 1;
        let (tx, rx) = outbound_queue::<Arc<str>>(budget, OnClose::Discard);
        let handle = tx.handle();
        for n in 1..=FIT {
            assert_eq!(handle.push(frame(LEN)), Push::Queued, "frame {n} fits");
        }
        assert_eq!(rx.len(), FIT);
        assert_eq!(
            handle.push(frame(LEN)),
            Push::Overflow(Overflow {
                queued_bytes: FIT * LEN,
                queued_frames: FIT,
                frame_bytes: LEN,
            }),
            "the next frame's charge crosses the budget by one byte"
        );

        // the same frames with one more byte of budget all fit
        let (tx, rx) = outbound_queue::<Arc<str>>(budget + 1, OnClose::Discard);
        let handle = tx.handle();
        for _ in 0..=FIT {
            assert_eq!(handle.push(frame(LEN)), Push::Queued);
        }
        assert_eq!(rx.len(), FIT + 1);
    }

    /// Frames with no payload are bounded too: a budget holds one overhead's
    /// worth of them each, so an endless run of empty frames overflows.
    #[test]
    fn zero_length_frames_are_bounded() {
        const FIT: usize = 10;
        let (tx, rx) =
            outbound_queue::<Arc<str>>(FIT * OUTBOUND_FRAME_OVERHEAD_BYTES, OnClose::Discard);
        let handle = tx.handle();
        for _ in 0..FIT {
            assert_eq!(handle.push(frame(0)), Push::Queued);
        }
        assert_eq!(rx.len(), FIT);
        assert_eq!(rx.queued_bytes(), 0, "no payload at all");
        assert_eq!(
            handle.push(frame(0)),
            Push::Overflow(Overflow {
                queued_bytes: 0,
                queued_frames: FIT,
                frame_bytes: 0,
            })
        );
    }

    /// Only bytes bound the queue: thousands of small frames wait together
    /// while their charges fit, and come out in the order they went in.
    #[test]
    fn many_small_frames_fit_a_byte_budget() {
        const FRAMES: usize = 5000;
        const LEN: usize = 8;
        let budget = FRAMES * (LEN + OUTBOUND_FRAME_OVERHEAD_BYTES);
        let (tx, rx) = outbound_queue::<Arc<str>>(budget, OnClose::Discard);
        let handle = tx.handle();
        for n in 0..FRAMES {
            assert_eq!(handle.push(Arc::from(format!("{n:08}"))), Push::Queued);
        }
        assert_eq!(rx.len(), FRAMES);
        for n in 0..FRAMES {
            assert_eq!(&*rx.try_recv().expect("queued"), format!("{n:08}"));
        }
        assert_eq!(rx.queued_bytes(), 0);
    }

    /// A frame larger than the whole budget is queued into an empty queue —
    /// it is still one deliverable message — and overflows a non-empty one.
    #[test]
    fn an_oversized_frame_fits_only_an_empty_queue() {
        let budget = 2 * OUTBOUND_FRAME_OVERHEAD_BYTES + 10;
        let (tx, rx) = outbound_queue::<Arc<str>>(budget, OnClose::Discard);
        let handle = tx.handle();
        assert_eq!(handle.push(frame(5 * budget)), Push::Queued);
        assert_eq!(
            rx.try_recv().expect("the oversized frame").len(),
            5 * budget
        );

        assert_eq!(handle.push(frame(1)), Push::Queued);
        assert!(matches!(handle.push(frame(5 * budget)), Push::Overflow(_)));

        // a budget of zero is all exception: one frame at a time
        let (tx, rx) = outbound_queue::<Arc<str>>(0, OnClose::Discard);
        let handle = tx.handle();
        assert_eq!(handle.push(frame(3)), Push::Queued);
        assert_eq!(rx.try_recv().expect("the one frame").len(), 3);
        assert_eq!(handle.push(frame(3)), Push::Queued);
        assert!(matches!(handle.push(frame(0)), Push::Overflow(_)));
    }

    /// A frame the receiver took is no longer charged: the budget bounds
    /// what waits, so a draining receiver never overflows.
    #[test]
    fn a_taken_frame_frees_its_charge() {
        let budget = 2 * (10 + OUTBOUND_FRAME_OVERHEAD_BYTES);
        let (tx, rx) = outbound_queue::<Arc<str>>(budget, OnClose::Discard);
        let handle = tx.handle();
        for _ in 0..100 {
            assert_eq!(handle.push(frame(10)), Push::Queued);
            assert_eq!(handle.push(frame(10)), Push::Queued, "exactly the budget");
            assert_eq!(rx.try_recv().expect("queued").len(), 10);
            assert_eq!(rx.try_recv().expect("queued").len(), 10);
        }
        assert_eq!(rx.queued_bytes(), 0);
    }

    /// Dropping the owner closes the queue: a discarding queue hands out
    /// nothing more, a draining one hands out what was queued first.
    #[test]
    fn a_close_discards_or_drains() {
        let (tx, rx) = outbound_queue::<Arc<str>>(1000, OnClose::Discard);
        let handle = tx.handle();
        assert_eq!(handle.push(frame(1)), Push::Queued);
        drop(tx);
        assert!(rx.is_closed());
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
        assert_eq!(
            handle.push(frame(1)),
            Push::Refused,
            "a handle is not an owner"
        );

        let (tx, rx) = outbound_queue::<Arc<str>>(1000, OnClose::Drain);
        assert_eq!(tx.handle().push(frame(1)), Push::Queued);
        drop(tx);
        assert_eq!(rx.try_recv().expect("drained").len(), 1);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
    }

    /// An overflowed queue stays open until its owner closes it, so the
    /// receiver reads the close only once the owner has recorded why.
    #[test]
    fn an_overflow_waits_for_the_owners_close() {
        let (tx, rx) = outbound_queue::<Arc<str>>(1, OnClose::Drain);
        let handle = tx.handle();
        assert_eq!(handle.push(frame(1)), Push::Queued);
        assert!(matches!(handle.push(frame(1)), Push::Overflow(_)));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        assert!(rx.recv().now_or_never().is_none(), "not closed yet");
        drop(tx);
        assert_eq!(rx.recv().now_or_never(), Some(None));
    }

    /// A waiting receiver is woken by a push and by the close, and a dropped
    /// receiver refuses every later push.
    #[tokio::test]
    async fn the_receiver_is_woken_and_its_drop_refuses() {
        let (tx, rx) = outbound_queue::<Arc<str>>(1000, OnClose::Discard);
        let handle = tx.handle();
        let reader = tokio::spawn(async move {
            let first = rx.recv().await;
            let second = rx.recv().await;
            (first, second)
        });
        tokio::task::yield_now().await;
        assert_eq!(handle.push(frame(3)), Push::Queued);
        tokio::task::yield_now().await;
        drop(tx);
        let (first, second) = reader.await.expect("reader task");
        assert_eq!(first.expect("the pushed frame").len(), 3);
        assert_eq!(second, None, "then the close");

        let (tx, rx) = outbound_queue::<Arc<str>>(1000, OnClose::Discard);
        drop(rx);
        assert_eq!(tx.handle().push(frame(1)), Push::Refused);
    }
}
