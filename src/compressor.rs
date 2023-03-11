use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdEncoder;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

use crate::transformer::AddTransformer;
use crate::transformer::Stats;
use crate::transformer::Transformer;

const RAW_FRAME_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct Compressor<'a> {
    internal_buf: ZstdEncoder<Vec<u8>>,
    prev_buf: BytesMut,
    size_counter: usize,
    _comp_num: usize,
    chunks: Vec<u8>,
    is_last: bool,
    finished: bool,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> Compressor<'_> {
    pub fn new(comp_num: usize, last: bool) -> Compressor<'a> {
        Compressor {
            internal_buf: ZstdEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK)),
            prev_buf: BytesMut::with_capacity(RAW_FRAME_SIZE + CHUNK),
            size_counter: 0,
            _comp_num: comp_num,
            chunks: Vec::new(),
            is_last: last,
            finished: false,
            next: None,
        }
    }
}

impl<'a> AddTransformer<'a> for Compressor<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for Compressor<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        if self.size_counter + buf.len() > RAW_FRAME_SIZE {
            let dif = self.size_counter - RAW_FRAME_SIZE;
            self.internal_buf.write_buf(&mut buf.split_to(dif)).await?;
            self.internal_buf.shutdown().await?;
            self.prev_buf.extend_from_slice(self.internal_buf.get_ref());
            self.add_skippable(finished).await;
            self.chunks.push(u8::try_from(self.prev_buf.len() / CHUNK)?)
        } else {
            self.internal_buf.write_buf(buf).await?;
        }

        // Add the "last" skippable frame
        if !self.finished && finished {
            self.internal_buf.shutdown().await?;
            self.prev_buf.extend_from_slice(self.internal_buf.get_ref());
            self.add_skippable(finished).await;
            self.chunks.push(u8::try_from(self.prev_buf.len() / CHUNK)?);
            self.finished = true;
        }

        if let Some(next) = &mut self.next {
            if self.prev_buf.len() / CHUNK > 0 {
                next.process_bytes(&mut self.prev_buf.split_to(CHUNK).freeze(), finished)
                    .await
            } else {
                next.process_bytes(&mut self.prev_buf.split().freeze(), finished)
                    .await
            }
        } else {
            Ok(false)
        }
    }
    async fn get_info(&mut self, _is_last: bool) -> Result<Vec<Stats>> {
        todo!();
    }
}

impl Compressor<'_> {
    async fn add_skippable(&mut self, finished: bool) {
        // Add the frame only when finished == true and is_last
        if !(finished == true && self.is_last) {
            if CHUNK - (self.prev_buf.len() % CHUNK) > 8 {
                self.prev_buf.extend(create_skippable_padding_frame(
                    CHUNK - (self.prev_buf.len() % CHUNK),
                ));
            } else {
                self.prev_buf.extend(create_skippable_padding_frame(
                    (CHUNK - (self.prev_buf.len() % CHUNK)) + CHUNK,
                ));
            }
        }
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
