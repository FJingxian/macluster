use std::io::{self, Cursor, Read, Write};

use macluster_protocol::framing::{
    ChunkAssembler, FrameError, MAX_CHUNK_BYTES, MAX_FRAME_BYTES, read_frame, write_frame,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Message {
    kind: String,
    id: u64,
}

struct FragmentedReader {
    bytes: Cursor<Vec<u8>>,
    max_read: usize,
}

impl Read for FragmentedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let max_read = self.max_read.min(buf.len());
        self.bytes.read(&mut buf[..max_read])
    }
}

struct CountedReader {
    bytes: Cursor<Vec<u8>>,
}

impl Read for CountedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.bytes.read(buf)
    }
}

impl Write for CountedReader {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.get_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn framing_reassembles_partial_reads() {
    let expected = Message {
        kind: "status".into(),
        id: 42,
    };
    let mut encoded = Vec::new();
    write_frame(&mut encoded, &expected).unwrap();
    let mut reader = FragmentedReader {
        bytes: Cursor::new(encoded),
        max_read: 2,
    };

    assert_eq!(
        read_frame::<_, Message>(&mut reader).unwrap(),
        Some(expected)
    );
    assert_eq!(read_frame::<_, Message>(&mut reader).unwrap(), None);
}

#[test]
fn oversized_frame_is_rejected_before_payload_read() {
    let mut input = CountedReader {
        bytes: Cursor::new(((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec()),
    };

    assert!(matches!(
        read_frame::<_, Message>(&mut input),
        Err(FrameError::FrameTooLarge { .. })
    ));
    assert_eq!(input.bytes.position(), 4);
}

#[test]
fn truncated_frame_reports_eof_without_returning_partial_message() {
    let bytes = [0, 0, 0, 8, b'{', b'}'];
    let error = read_frame::<_, Message>(&mut Cursor::new(bytes)).unwrap_err();

    assert!(matches!(
        error,
        FrameError::Truncated {
            expected: 8,
            actual: 2
        }
    ));
}

#[test]
fn chunk_replay_checks_offset_and_digest() {
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let mut upload = ChunkAssembler::new(3, digest).unwrap();

    assert_eq!(upload.push(0, b"ab").unwrap(), 2);
    assert_eq!(upload.push(0, b"ab").unwrap(), 2);
    assert_eq!(upload.push(2, b"c").unwrap(), 3);
    assert_eq!(upload.finish().unwrap(), b"abc");
}

#[test]
fn chunk_overlap_and_bad_digest_are_rejected() {
    let mut upload = ChunkAssembler::new(3, &"0".repeat(64)).unwrap();
    upload.push(0, b"ab").unwrap();
    assert!(matches!(
        upload.push(1, b"bc"),
        Err(FrameError::ConflictingChunk)
    ));
    upload.push(2, b"c").unwrap();
    assert!(matches!(upload.finish(), Err(FrameError::DigestMismatch)));
}

#[test]
fn chunk_size_limit_is_enforced() {
    let mut upload = ChunkAssembler::new(8 * 1024 * 1024, &"0".repeat(64)).unwrap();
    let payload = vec![b'x'; MAX_CHUNK_BYTES + 1];
    assert!(matches!(
        upload.push(0, &payload),
        Err(FrameError::ChunkTooLarge { .. })
    ));
}
