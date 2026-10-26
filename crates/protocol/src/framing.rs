use std::io::{self, Read, Write};

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("frame payload is empty")]
    EmptyFrame,
    #[error("frame is truncated: expected {expected} bytes, received {actual}")]
    Truncated { expected: usize, actual: usize },
    #[error("frame payload is {actual} bytes; maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("invalid JSON payload: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chunk is {actual} bytes; maximum is {maximum}")]
    ChunkTooLarge { actual: usize, maximum: usize },
    #[error("chunk offset {actual} does not match the expected offset {expected}")]
    UnexpectedOffset { expected: u64, actual: u64 },
    #[error("chunk overlaps committed data with different bytes")]
    ConflictingChunk,
    #[error("chunk exceeds the declared payload length")]
    PayloadOverflow,
    #[error("SHA-256 must contain exactly 64 hexadecimal characters")]
    InvalidDigest,
    #[error("completed payload SHA-256 does not match the declared digest")]
    DigestMismatch,
    #[error("payload is incomplete: expected {expected} bytes, received {actual}")]
    IncompletePayload { expected: u64, actual: u64 },
}

/// Writes a length-delimited JSON message. The limit applies to encoded JSON bytes.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() {
        return Err(FrameError::EmptyFrame);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            actual: payload.len(),
            maximum: MAX_FRAME_BYTES,
        });
    }

    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Reads one frame, returning `None` only for clean EOF between frames.
pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<Option<T>, FrameError> {
    let mut header = [0_u8; 4];
    let header_bytes = read_prefix(reader, &mut header)?;
    if header_bytes == 0 {
        return Ok(None);
    }
    if header_bytes != header.len() {
        return Err(FrameError::Truncated {
            expected: header.len(),
            actual: header_bytes,
        });
    }

    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(FrameError::EmptyFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        });
    }

    let mut payload = vec![0_u8; length];
    let actual = read_prefix(reader, &mut payload)?;
    if actual != length {
        return Err(FrameError::Truncated {
            expected: length,
            actual,
        });
    }
    Ok(Some(serde_json::from_slice(&payload)?))
}

fn read_prefix<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..])? {
            0 => break,
            count => offset += count,
        }
    }
    Ok(offset)
}

/// Reassembles an idempotent, bounded, content-addressed upload.
pub struct ChunkAssembler {
    expected_size: u64,
    expected_digest: [u8; 32],
    bytes: Vec<u8>,
}

impl ChunkAssembler {
    pub fn new(expected_size: u64, expected_sha256: &str) -> Result<Self, FrameError> {
        if expected_size > MAX_SNAPSHOT_BYTES {
            return Err(FrameError::PayloadOverflow);
        }
        Ok(Self {
            expected_size,
            expected_digest: parse_digest(expected_sha256)?,
            bytes: Vec::new(),
        })
    }

    /// Appends the next chunk. A byte-identical replay is accepted; gaps and conflicting overlaps fail.
    pub fn push(&mut self, offset: u64, chunk: &[u8]) -> Result<u64, FrameError> {
        if chunk.len() > MAX_CHUNK_BYTES {
            return Err(FrameError::ChunkTooLarge {
                actual: chunk.len(),
                maximum: MAX_CHUNK_BYTES,
            });
        }
        let end = offset
            .checked_add(chunk.len() as u64)
            .ok_or(FrameError::PayloadOverflow)?;
        if end > self.expected_size {
            return Err(FrameError::PayloadOverflow);
        }

        let current = self.bytes.len() as u64;
        if offset < current {
            if end <= current && self.bytes[offset as usize..end as usize] == *chunk {
                return Ok(current);
            }
            return Err(FrameError::ConflictingChunk);
        }
        if offset > current {
            return Err(FrameError::UnexpectedOffset {
                expected: current,
                actual: offset,
            });
        }

        self.bytes
            .try_reserve(chunk.len())
            .map_err(|_| FrameError::PayloadOverflow)?;
        self.bytes.extend_from_slice(chunk);
        Ok(self.bytes.len() as u64)
    }

    pub fn finish(self) -> Result<Vec<u8>, FrameError> {
        if self.bytes.len() as u64 != self.expected_size {
            return Err(FrameError::IncompletePayload {
                expected: self.expected_size,
                actual: self.bytes.len() as u64,
            });
        }
        if sha256(&self.bytes)? != self.expected_digest {
            return Err(FrameError::DigestMismatch);
        }
        Ok(self.bytes)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> Result<String, FrameError> {
    let digest = sha256(bytes)?;
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn parse_digest(value: &str) -> Result<[u8; 32], FrameError> {
    if value.len() != 64 {
        return Err(FrameError::InvalidDigest);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(FrameError::InvalidDigest)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(FrameError::InvalidDigest)?;
        digest[index] = ((high << 4) | low) as u8;
    }
    Ok(digest)
}

#[cfg(target_vendor = "apple")]
fn sha256(bytes: &[u8]) -> Result<[u8; 32], FrameError> {
    unsafe extern "C" {
        fn CC_SHA256(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
    }

    let len = u32::try_from(bytes.len()).map_err(|_| FrameError::PayloadOverflow)?;
    let mut output = [0_u8; 32];
    // CommonCrypto's one-shot routine writes exactly 32 digest bytes.
    let result = unsafe { CC_SHA256(bytes.as_ptr(), len, output.as_mut_ptr()) };
    if result.is_null() {
        return Err(FrameError::DigestMismatch);
    }
    Ok(output)
}

#[cfg(not(target_vendor = "apple"))]
fn sha256(_bytes: &[u8]) -> Result<[u8; 32], FrameError> {
    Err(FrameError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "SHA-256 upload verification is supported on macOS only",
    )))
}
