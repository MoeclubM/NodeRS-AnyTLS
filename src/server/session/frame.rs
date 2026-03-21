use anyhow::Error;
use md5::{Digest as Md5Digest, Md5};
use std::collections::HashMap;

pub(super) const CMD_WASTE: u8 = 0;
pub(super) const CMD_SYN: u8 = 1;
pub(super) const CMD_PSH: u8 = 2;
pub(super) const CMD_FIN: u8 = 3;
pub(super) const CMD_SETTINGS: u8 = 4;
pub(super) const CMD_ALERT: u8 = 5;
pub(super) const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub(super) const CMD_SYNACK: u8 = 7;
pub(super) const CMD_HEART_REQUEST: u8 = 8;
pub(super) const CMD_HEART_RESPONSE: u8 = 9;
pub(super) const CMD_SERVER_SETTINGS: u8 = 10;
pub(super) const MAX_FRAME_PAYLOAD_LEN: usize = u16::MAX as usize;
pub(super) const SMALL_PAYLOAD_LEN: usize = 1024;
pub(super) const MEDIUM_PAYLOAD_LEN: usize = 16 * 1024;
pub(super) const COMPACT_FRAME_PAYLOAD_THRESHOLD: usize = 8 * 1024;
pub(super) const SMALL_DATA_FRAME_FLUSH_THRESHOLD: usize = 4 * 1024;
pub(super) const SMALL_DOWNLOAD_COALESCE_TARGET: usize = 24 * 1024;
pub(super) const SMALL_DOWNLOAD_COALESCE_WAIT: std::time::Duration =
    std::time::Duration::from_millis(2);
#[cfg(target_env = "musl")]
pub(super) const MUSL_LARGE_DOWNLOAD_COALESCE_SPAN: usize = 24 * 1024;
pub(super) const SMALL_UPLOAD_BATCH_SIZE: usize = 96 * 1024;
pub(super) const LARGE_UPLOAD_BATCH_SIZE: usize = 256 * 1024;
pub(super) const DEFAULT_UPLOAD_BATCH_SIZE: usize = 128 * 1024;
#[cfg(target_env = "musl")]
pub(super) const SMALL_UPLOAD_BATCH_IOVECS: usize = 80;
#[cfg(not(target_env = "musl"))]
pub(super) const SMALL_UPLOAD_BATCH_IOVECS: usize = 96;
pub(super) const LARGE_UPLOAD_BATCH_IOVECS: usize = 42;
pub(super) const DEFAULT_UPLOAD_BATCH_IOVECS: usize = 64;
pub(super) const MAX_UPLOAD_BATCH_IOVECS: usize = SMALL_UPLOAD_BATCH_IOVECS;
#[cfg(target_env = "musl")]
pub(super) const LARGE_INBOUND_SEGMENT_LEN: usize = 32 * 1024;
pub(super) const STREAM_INBOUND_QUEUE_CAPACITY: usize = 4096;
pub(super) const MAX_STREAMS_PER_SESSION: usize = 256;
// This queue doubles as the effective upload window between the AnyTLS session and the
// outbound TCP socket. 4 MiB removed the old 80 ms weak-link ceiling, but the current
// 200 ms benchmark profile still benefits from more recovery headroom after loss bursts.
pub(super) const STREAM_INBOUND_QUEUE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PayloadTier {
    Small,
    Medium,
    Large,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct UploadBatchPolicy {
    pub(super) max_bytes: usize,
    pub(super) max_iovecs: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct FrameHeader {
    pub(super) cmd: u8,
    pub(super) stream_id: u32,
    pub(super) length: u16,
}

pub(super) fn should_flush_frame(cmd: u8, payload_len: usize) -> bool {
    !matches!(cmd, CMD_PSH) || payload_len <= SMALL_DATA_FRAME_FLUSH_THRESHOLD
}

pub(super) fn payload_tier(payload_len: usize) -> PayloadTier {
    if payload_len <= SMALL_PAYLOAD_LEN {
        PayloadTier::Small
    } else if payload_len <= MEDIUM_PAYLOAD_LEN {
        PayloadTier::Medium
    } else {
        PayloadTier::Large
    }
}

pub(super) fn upload_batch_policy(first_chunk_len: usize) -> UploadBatchPolicy {
    match payload_tier(first_chunk_len) {
        PayloadTier::Small => UploadBatchPolicy {
            max_bytes: SMALL_UPLOAD_BATCH_SIZE,
            max_iovecs: SMALL_UPLOAD_BATCH_IOVECS,
        },
        PayloadTier::Medium => UploadBatchPolicy {
            max_bytes: DEFAULT_UPLOAD_BATCH_SIZE,
            max_iovecs: DEFAULT_UPLOAD_BATCH_IOVECS,
        },
        PayloadTier::Large => UploadBatchPolicy {
            max_bytes: LARGE_UPLOAD_BATCH_SIZE,
            max_iovecs: LARGE_UPLOAD_BATCH_IOVECS,
        },
    }
}

pub(super) fn download_coalesce_target(initial_read: usize) -> Option<usize> {
    if initial_read <= SMALL_DATA_FRAME_FLUSH_THRESHOLD {
        return Some(SMALL_DOWNLOAD_COALESCE_TARGET.min(MAX_FRAME_PAYLOAD_LEN));
    }
    // Large reads can opportunistically fold another immediately-available chunk into the
    // same frame without waiting, which reduces per-frame overhead under bulk concurrency.
    // Musl tends to lose more from letting a single stream keep coalescing all the way to the
    // frame limit under high parallelism, so cap it to one extra medium-sized span there.
    if initial_read >= MEDIUM_PAYLOAD_LEN && initial_read < MAX_FRAME_PAYLOAD_LEN {
        #[cfg(target_env = "musl")]
        return Some(
            initial_read
                .saturating_add(MUSL_LARGE_DOWNLOAD_COALESCE_SPAN)
                .min(MAX_FRAME_PAYLOAD_LEN),
        );
        #[cfg(not(target_env = "musl"))]
        return Some(MAX_FRAME_PAYLOAD_LEN);
    }
    None
}

pub(super) fn parse_settings(bytes: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

pub(super) fn padding_md5(lines: &[String]) -> String {
    let mut hasher = Md5::new();
    hasher.update(lines.join("\n").as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn is_eof(error: &Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
}
