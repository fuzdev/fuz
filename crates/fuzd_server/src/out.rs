//! Outgoing-frame plumbing for the per-connection writer task.
//!
//! Streaming responses mean the read loop cannot own the socket
//! writer: a background collector pushes frames for a subscription while
//! the read loop is parked on the next request. So every connection runs
//! a dedicated **writer task** that owns the write half and pulls
//! pre-encoded [`OutFrame`]s off a bounded channel. The read loop and the
//! workload collectors are both producers on that channel.

use fuz_wire::{Action, ActionId, FrameFlags, HEADER_BYTES, MAX_FRAME, ProtoError, encode_payload};

/// A pre-encoded outgoing frame queued for a connection's writer task.
#[derive(Debug)]
pub struct OutFrame {
    pub request_id: u32,
    pub action: ActionId,
    pub flags: FrameFlags,
    pub body: Vec<u8>,
}

impl OutFrame {
    /// A complete single-frame response (flagged [`FrameFlags::FINAL`]).
    ///
    /// # Errors
    ///
    /// Returns [`ProtoError::Encode`] if the payload fails to serialize, or
    /// [`ProtoError::FrameTooLarge`] if it does not fit one frame — checked here,
    /// before the frame is queued, so the writer never holds one it must refuse.
    pub fn response<A: Action>(request_id: u32, payload: &A) -> Result<Self, ProtoError> {
        Ok(Self {
            request_id,
            action: A::ID,
            flags: FrameFlags::FINAL,
            body: encode_fitting(payload)?,
        })
    }
}

/// Encode `payload`, refusing a body too large for one frame.
fn encode_fitting<A: Action>(payload: &A) -> Result<Vec<u8>, ProtoError> {
    let body = encode_payload(payload)?;
    let declared =
        u32::try_from(body.len()).map_or(u32::MAX, |len| len.saturating_add(HEADER_BYTES));
    if declared > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge {
            declared,
            limit: MAX_FRAME,
        });
    }
    Ok(body)
}

/// Bounded sender to a connection's writer task.
///
/// Responses use `.send().await` (await room — natural backpressure onto
/// the read loop). Collectors never await room: every collector frame, a
/// subscription's first snapshot included, goes out by `try_send`, dropping +
/// resyncing on a full channel, so one slow connection can't stall a collector
/// and with it every other subscriber of that workload.
pub type OutTx = tokio::sync::mpsc::Sender<OutFrame>;

/// Receiver half, owned by the writer task.
pub type OutRx = tokio::sync::mpsc::Receiver<OutFrame>;

/// Per-connection outgoing channel depth. When a collector fills this, the
/// subscription drops its delta backlog and resyncs with a fresh snapshot.
pub const OUT_CHANNEL_CAP: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_wire::{WatchEvent, WatchEventKind, WatcherEventFrame};

    fn event_frame(path_len: usize) -> WatcherEventFrame {
        WatcherEventFrame {
            events: vec![WatchEvent {
                path: "x".repeat(path_len),
                kind: WatchEventKind::Modified,
            }],
        }
    }

    #[test]
    fn response_refuses_a_body_past_the_frame_limit_and_takes_one_at_it() {
        let budget = (MAX_FRAME - HEADER_BYTES) as usize;
        // Overhead of the frame around the path, at a length with the same varint width.
        let overhead = encode_payload(&event_frame(budget - 64)).unwrap().len() - (budget - 64);
        let at = event_frame(budget - overhead);
        assert_eq!(encode_payload(&at).unwrap().len(), budget);
        assert!(
            OutFrame::response(1, &at).is_ok(),
            "a body at the limit fits"
        );
        let over = event_frame(budget - overhead + 1);
        assert!(matches!(
            OutFrame::response(1, &over),
            Err(ProtoError::FrameTooLarge { declared, limit: MAX_FRAME }) if declared == MAX_FRAME + 1
        ));
    }
}
