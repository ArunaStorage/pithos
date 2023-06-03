use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdEncoder;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

use crate::transformer::AddTransformer;
use crate::notifications::Data;
use crate::notifications::Notifications;
use crate::transformer::Transformer;

const RAW_FRAME_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct ZstdEnc<'a> {
    internal_buf: ZstdEncoder<Vec<u8>>,
    prev_buf: BytesMut,
    size_counter: usize,
    _comp_num: usize,
    chunks: Vec<u8>,
    is_last: bool,
    finished: bool,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> ZstdEnc<'a> {
    #[allow(dead_code)]
    pub fn new(comp_num: usize, last: bool) -> ZstdEnc<'a> {
        ZstdEnc {
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

impl<'a> AddTransformer<'a> for ZstdEnc<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for ZstdEnc<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        // Create a new frame if buf would increase size_counter to more than RAW_FRAME_SIZE
        while self.size_counter + buf.len() > RAW_FRAME_SIZE {
            // Check how much bytes are missing
            let dif = RAW_FRAME_SIZE - self.size_counter;
            // Make sure that dif is <= RAW_FRAME_SIZE
            assert!(dif <= RAW_FRAME_SIZE);
            self.internal_buf.write_buf(&mut buf.split_to(dif)).await?;
            // Shut the writer down -> Calls flush()
            self.internal_buf.shutdown().await?;
            // Get data from the vector buffer to the "prev_buf" -> Output buffer
            self.prev_buf.extend_from_slice(self.internal_buf.get_ref());
            // Create a new Encoder
            self.internal_buf = ZstdEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK));
            // Add a skippable frame to the output buffer
            self.add_skippable().await;
            // Reset the size_counter
            self.size_counter = 0;
            // Add the number of chunks to the chunksvec (for indexing)
            self.chunks.push(u8::try_from(self.prev_buf.len() / CHUNK)?);

            // Try to write the buf to the "next" in the chain, even if the buf is empty
            if let Some(next) = &mut self.next {
                // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
                next.process_bytes(
                    &mut self.prev_buf.split().freeze(),
                    self.finished && self.prev_buf.is_empty(),
                )
                .await?;
            } else {
                return Err(anyhow!(
                    "This compressor is designed to always contain a 'next'"
                ));
            }
        }

        // Only write if the buffer contains data and the current process is not finished
        if !buf.is_empty() && !self.finished {
            self.size_counter += buf.len();
            self.internal_buf.write_buf(buf).await?;
        }

        // Add the "last" skippable frame if the previous writer is finished but this one is not!
        if !self.finished && finished && buf.is_empty() {
            self.internal_buf.shutdown().await?;
            self.prev_buf.extend_from_slice(self.internal_buf.get_ref());
            if !self.is_last {
                self.add_skippable().await;
            };
            self.chunks.push(u8::try_from(self.prev_buf.len() / CHUNK)?);
            self.finished = true;
            self.notify(&mut vec![Notifications::Message(Data {
                recipient: "FOOTER".to_string(),
                info: Some(self.chunks.clone()),
            })])
            .await?;

            // Try to write the buf to the "next" in the chain, even if the buf is empty
            if let Some(next) = &mut self.next {
                // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
                next.process_bytes(
                    &mut self.prev_buf.split().freeze(),
                    self.finished && self.prev_buf.is_empty(),
                )
                .await?;
            } else {
                return Err(anyhow!(
                    "This compressor is designed to always contain a 'next'"
                ));
            }
        }

        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
            next.process_bytes(
                &mut self.prev_buf.split().freeze(),
                self.finished && self.prev_buf.is_empty(),
            )
            .await
        } else {
            Err(anyhow!(
                "This compressor is designed to always contain a 'next'"
            ))
        }
    }
    async fn notify(&mut self, notes: &mut Vec<Notifications>) -> Result<()> {
        if let Some(next) = &mut self.next {
            notes.push(Notifications::Response(Data {
                recipient: format!("COMPRESSOR_CHUNKS_{}", self._comp_num),
                info: Some(self.chunks.clone()),
            }));
            next.notify(notes).await?
        }
        Ok(())
    }
}

impl ZstdEnc<'_> {
    async fn add_skippable(&mut self) {
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
