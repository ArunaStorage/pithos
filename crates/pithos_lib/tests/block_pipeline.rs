mod common;

use common::util::{fixture, open, private_key};
use pithos_lib::archive::AccessKeys;
use std::io::Write;

struct RecordingSink(Vec<u8>);

impl Write for RecordingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn public_archive_rejects_a_bad_block_marker_without_sink_output() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let mut bytes = std::fs::read(&path).unwrap();
    let marker = bytes
        .windows(4)
        .position(|window| window == b"BLCK")
        .unwrap();
    bytes[marker] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    let archive = open(&path, AccessKeys::new().with_key(private_key("recipient1")));
    let mut sink = RecordingSink(Vec::new());
    assert!(archive.copy_to("data", &mut sink).is_err());
    assert!(sink.0.is_empty());
}
