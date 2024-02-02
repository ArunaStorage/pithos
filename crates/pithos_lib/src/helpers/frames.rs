use crate::pithos::structs::ZSTD_MAGIC_BYTES_SKIPPABLE_15;
use anyhow::anyhow;
use byteorder::{LittleEndian, WriteBytesExt};
use bytes::Bytes;
use tracing::error;

#[tracing::instrument(level = "trace", skip(size))]
#[inline]
pub fn create_skippable_padding_frame(size: usize) -> anyhow::Result<Bytes> {
    if size < 8 {
        error!(size = size, "Size too small");
        return Err(anyhow!("{size} is too small, minimum is 8 bytes"));
    }
    // Add frame_header
    let mut frame = ZSTD_MAGIC_BYTES_SKIPPABLE_15.to_vec();
    // 4 Bytes (little-endian) for size
    WriteBytesExt::write_u32::<LittleEndian>(&mut frame, size as u32 - 8)?;
    frame.extend(vec![0; size - 8]);
    Ok(Bytes::from(frame))
}
