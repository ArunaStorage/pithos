use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdEncoder;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

use crate::transformer::Transformer;

const RAW_FRAME_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct Compressor {
    internal_buf: ZstdEncoder<Vec<u8>>,
    overflow: BytesMut,
    size_counter: usize,
    current_chunk: u8,
    comp_num: usize,
    chunks: Vec<u8>,
    closed: bool,
}

impl Compressor {
    pub async fn new(comp_num: usize) -> Self {
        Compressor {
            internal_buf: ZstdEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + 65_536)),
            overflow: BytesMut::with_capacity(2 * CHUNK),
            size_counter: 0,
            current_chunk: 0,
            comp_num: comp_num,
            chunks: Vec::new(),
            closed: false,
        }
    }

    pub async fn get_chunk_list(&self) -> (usize, Vec<u8>) {
        (self.comp_num, self.chunks.clone())
    }
}

#[async_trait::async_trait]
impl Transformer for Compressor {
    async fn write_bytes(&mut self, buf: &mut bytes::Bytes) -> Result<()> {
        // Create a new frame if the size_counter is larger with the new buffer
        if self.size_counter + buf.len() > RAW_FRAME_SIZE {
            if self.overflow.len() != 0 {
                dbg!(self.overflow.len(), self.chunks.len());
                return Err(anyhow!("Overflow is not empty!"));
            }
            let dif = self.size_counter - RAW_FRAME_SIZE;
            // Write the "last" bytes for this RAW_CHUNK_SIZE
            self.internal_buf.write_buf(&mut buf.split_to(dif)).await?;
            self.internal_buf.shutdown().await?;
            self.overflow.extend_from_slice(
                &self.internal_buf.get_ref()[self.current_chunk as usize * CHUNK..],
            );
            if self.overflow.len() != 0 {
                if CHUNK - (self.overflow.len() % CHUNK) > 8 {
                    self.overflow.extend(create_skippable_padding_frame(
                        CHUNK - (self.overflow.len() % CHUNK),
                    ));
                    self.current_chunk += 1;
                } else {
                    self.overflow.extend(create_skippable_padding_frame(
                        (CHUNK - (self.overflow.len() % CHUNK)) + CHUNK,
                    ));
                    self.current_chunk += 2;
                }
            }
            self.chunks.push(self.current_chunk);
            self.internal_buf = ZstdEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + 65_536));
            self.size_counter = 0;
            self.current_chunk = 0;
        }
        self.size_counter += self.internal_buf.write_buf(buf).await?;
        self.internal_buf.flush().await?;
        Ok(())
    }

    async fn get_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.has_chunk().await? {
            if self.overflow.len() != 0 {
                if self.overflow.len() > CHUNK {
                    return Ok(Some(self.overflow.split_to(CHUNK).freeze()));
                } else {
                    return Ok(Some(self.overflow.split().freeze()));
                }
            }
            if self.internal_buf.get_ref().len() == 0 && self.overflow.len() == 0 {
                return Ok(None);
            }
            let res = Ok(Some(Bytes::copy_from_slice(
                &self.internal_buf.get_ref()[(self.current_chunk as usize * CHUNK)
                    ..(self.current_chunk as usize + 1) * CHUNK],
            )));
            self.current_chunk += 1;
            res
        } else {
            Ok(None)
        }
    }

    async fn finish(&mut self, is_last: bool) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.internal_buf.shutdown().await?;
        self.closed = true;
        self.overflow
            .extend_from_slice(&self.internal_buf.get_ref()[self.current_chunk as usize * CHUNK..]);
        self.internal_buf.get_mut().clear();

        if self.overflow.len() % CHUNK != 0 && is_last == false {
            if CHUNK - (self.overflow.len() % CHUNK) > 8 {
                self.overflow.extend(create_skippable_padding_frame(
                    CHUNK - (self.overflow.len() % CHUNK),
                ));
                self.current_chunk += 1;
            } else {
                self.overflow.extend(create_skippable_padding_frame(
                    (CHUNK - (self.overflow.len() % CHUNK)) + CHUNK,
                ));
                self.current_chunk += 2;
            }
        }
        if self.current_chunk == 0 {
            self.chunks.push(1);
        } else {
            self.chunks.push(self.current_chunk)
        }

        Ok(())
    }

    async fn has_chunk(&mut self) -> Result<bool> {
        if self.closed {
            return Ok(true);
        }

        if self.overflow.len() != 0 {
            return Ok(true);
        }
        Ok(self.internal_buf.get_ref()[self.current_chunk as usize * CHUNK..].len() >= CHUNK)
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

fn _build_footer_frames(_frames: Vec<(usize, Vec<u8>)>) -> Result<Vec<Bytes>> {
    Ok(Vec::new())
}
