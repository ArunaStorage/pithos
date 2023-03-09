use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdEncoder;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

use crate::transformer::Transformer;

const RAW_CHUNK_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct Compressor {
    internal_buf: ZstdEncoder<Vec<u8>>,
    overflow: BytesMut,
    size_counter: usize,
    current_chunk: u8,
    comp_num: usize,
    chunks: Vec<u8>,
}

impl Compressor {
    pub async fn new(comp_num: usize) -> Self {
        Compressor {
            internal_buf: ZstdEncoder::new(Vec::with_capacity(RAW_CHUNK_SIZE + 65_536)),
            overflow: BytesMut::with_capacity(2 * CHUNK),
            size_counter: 0,
            current_chunk: 0,
            comp_num: comp_num,
            chunks: Vec::new(),
        }
    }

    async fn has_chunk(&mut self) -> Result<bool> {
        if self.overflow.len() != 0 {
            return Ok(true);
        }

        if self.size_counter > 6 * CHUNK {
            self.internal_buf.flush().await?;
        }

        Ok(self.internal_buf.get_ref().len() / CHUNK > self.current_chunk.into())
    }
}

#[async_trait::async_trait]
impl Transformer for Compressor {
    async fn write(&mut self, buf: &mut bytes::Bytes) -> Result<()> {
        if self.size_counter + buf.len() > RAW_CHUNK_SIZE {
            let dif = self.size_counter - RAW_CHUNK_SIZE;
            // Write the "last" bytes for this RAW_CHUNK_SIZE
            self.internal_buf.write_buf(&mut buf.split_to(dif)).await?;
            self.internal_buf.shutdown().await?;
            self.overflow
                .extend_from_slice(&self.internal_buf.get_ref());
            self.internal_buf = ZstdEncoder::new(Vec::with_capacity(RAW_CHUNK_SIZE + 65_536));
            self.chunks.push(self.current_chunk);
            self.size_counter = 0;
            self.current_chunk = 0;
        }

        self.size_counter += self.internal_buf.write_buf(buf).await?;
        Ok(())
    }

    async fn get_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.has_chunk().await? {
            if self.overflow.len() != 0 {
                if self.overflow.len() > CHUNK {
                    return Ok(Some(self.overflow.split_to(CHUNK).freeze()));
                } else {
                    if CHUNK - self.overflow.len() > 8 {
                        self.overflow
                            .extend(create_skippable_padding_frame(CHUNK - self.overflow.len()));
                        return Ok(Some(self.overflow.split().freeze()));
                    } else {
                        self.overflow.extend(create_skippable_padding_frame(
                            (CHUNK - self.overflow.len()) + CHUNK,
                        ));
                        return Ok(Some(self.overflow.split_to(CHUNK).freeze()));
                    }
                }
            }

            self.internal_buf.flush().await?;

            let res = Ok(Some(Bytes::copy_from_slice(
                &self.internal_buf.get_ref()
                    [self.current_chunk as usize..self.current_chunk as usize + CHUNK],
            )));
            self.current_chunk += 1;
            res
        } else {
            Ok(None)
        }
    }

    async fn finish(mut self, is_last: bool) -> Result<Vec<Bytes>> {
        self.internal_buf.shutdown().await?;
        let buffer = self.internal_buf.into_inner();

        Ok(Vec::new())
    }
}

fn create_skippable_padding_frame(size: usize) -> Result<Bytes> {
    if size < 8 {
        return Err(anyhow!("{size} is too small, minimum is 8 bytes"));
    }
    // Add frame_header
    let mut frame = hex::decode("502A4D18")?;
    // 4 Bytes (little-endian) for size
    WriteBytesExt::write_u32::<LittleEndian>(&mut frame, size as u32 - 8)?;
    frame.extend(vec![0; size - 8]);
    Ok(Bytes::from(frame))
}
