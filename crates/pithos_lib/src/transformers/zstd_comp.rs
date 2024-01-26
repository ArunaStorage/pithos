use std::sync::Arc;

use crate::notifications::Message;
use crate::notifications::Notifier;
use crate::structs::ProbeResult;
use crate::structs::ZSTD_MAGIC_BYTES_SKIPPABLE_15;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::Result;
use async_channel::Receiver;
use async_channel::Sender;
use async_channel::TryRecvError;
use async_compression::tokio::write::ZstdEncoder;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::BufMut;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;
use tracing::debug;
use tracing::error;

const RAW_FRAME_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct ZstdEnc {
    internal_buf: ZstdEncoder<Vec<u8>>,
    prev_buf: BytesMut,
    size_counter: usize,
    chunks: Vec<u8>,
    finished: bool,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    probe_result: ProbeResult,
}

impl ZstdEnc {
    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new() -> Self {
        ZstdEnc {
            internal_buf: ZstdEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK)),
            prev_buf: BytesMut::with_capacity(RAW_FRAME_SIZE + CHUNK),
            size_counter: 0,
            chunks: Vec::new(),
            finished: false,
            notifier: None,
            msg_receiver: None,
            idx: None,
            probe_result: ProbeResult::Unknown,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<(bool, bool)> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::ShouldFlush) => return Ok((true, false)),
                    Ok(Message::Finished) => {
                        return Ok((false, true));
                    }
                    Ok(Message::FileContext(ctx)) => {
                        if ctx.compression {
                            self.probe_result = ProbeResult::Compression;
                        } else {
                            self.probe_result = ProbeResult::Unknown;
                        }
                    }
                    Ok(_) => {}
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Closed) => {
                        error!("Message receiver closed");
                        return Err(anyhow!("Message receiver closed"));
                    }
                }
            }
        }
        Ok((false, false))
    }

    #[tracing::instrument(level = "trace", skip(self))]
    async fn probe_compression(&mut self) -> Result<bool> {
        let original_size = self.prev_buf.len();
        let mut compressor = ZstdEncoder::new(Vec::with_capacity(original_size + 100));
        compressor.write_all(&self.prev_buf).await?;
        compressor.shutdown().await?;
        if (original_size as f64 * 0.875) as usize > compressor.get_ref().len() {
            self.probe_result = ProbeResult::Compression;
            self.internal_buf.write_all(&self.prev_buf.split()).await?;
            Ok(false)
        } else {
            self.probe_result = ProbeResult::NoCompression;
            Ok(true)
        }
    }
}

#[async_trait::async_trait]
impl Transformer for ZstdEnc {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::ZstdCompressor, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        let Ok((should_flush, finished)) = self.process_messages() else {
            return Err(anyhow!("Error processing messages"));
        };

        if should_flush {
            debug!("flushed zstd encoder");
            self.internal_buf.write_all_buf(buf).await?;
            self.internal_buf.shutdown().await?;
            self.prev_buf.extend_from_slice(self.internal_buf.get_ref());
            self.internal_buf = ZstdEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK));
            buf.put(self.prev_buf.split().freeze());
            return Ok(());
        }

        match self.probe_result {
            ProbeResult::Compression => {}
            ProbeResult::Unknown => {
                self.prev_buf.put(buf.split());
                if finished || self.prev_buf.len() > 8192 {
                    if self.probe_compression().await? {
                        buf.put(self.prev_buf.split());
                    }
                } else if self.prev_buf.len() < 8192 {
                    return Ok(());
                }
            }
            ProbeResult::NoCompression => {
                // Skip all compression
                return Ok(());
            }
        }

        // Create a new frame if buf would increase size_counter to more than RAW_FRAME_SIZE
        if self.size_counter + buf.len() > RAW_FRAME_SIZE {
            let mut all_data = buf.split().freeze();

            while self.size_counter + all_data.len() >= RAW_FRAME_SIZE {
                // Check how much bytes are missing
                let dif = RAW_FRAME_SIZE - self.size_counter;
                // Make sure that dif is <= RAW_FRAME_SIZE
                assert!(dif <= RAW_FRAME_SIZE);
                self.internal_buf
                    .write_all_buf(&mut all_data.split_to(dif))
                    .await?;
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
                buf.put(self.prev_buf.split().freeze());
            }
            if !all_data.is_empty() {
                assert!(all_data.len() <= RAW_FRAME_SIZE);
                self.size_counter = all_data.len();
                self.internal_buf.write_all_buf(&mut all_data).await?;
            }

            return Ok(());
        }

        // Only write if the buffer contains data and the current process is not finished
        if !buf.is_empty() && !self.finished {
            self.size_counter += buf.len();
            assert!(self.size_counter <= RAW_FRAME_SIZE);
            self.internal_buf.write_buf(buf).await?;
        }

        // Add the "last" skippable frame if the previous writer is finished but this one is not!
        if !self.finished && finished && buf.is_empty() {
            self.internal_buf.shutdown().await?;
            self.prev_buf.extend_from_slice(self.internal_buf.get_ref());
            self.chunks.push(u8::try_from(self.prev_buf.len() / CHUNK)?);
            buf.put(self.prev_buf.split().freeze());
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
            }
            self.finished = true;
            return Ok(());
        }
        buf.put(self.prev_buf.split().freeze());
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}

impl ZstdEnc {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn add_skippable(&mut self) {
        // No skippable frame needed if the buffer is empty
        if self.prev_buf.is_empty() {
            return;
        }
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

#[tracing::instrument(level = "trace", skip(size))]
#[inline]
fn create_skippable_padding_frame(size: usize) -> Result<Bytes> {
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

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_zstd_encoder() {
        let mut encoder = ZstdEnc::new();
        let mut buf = BytesMut::new();
        buf.put(b"12345".as_slice());
        let (_, sx) = encoder.initialize(0).await;
        sx.send(Message::Finished).await.unwrap();
        encoder.process_bytes(&mut buf).await.unwrap();
        // Starts with magic zstd header (little-endian)
        assert!(buf.starts_with(&hex::decode("28B52FFD").unwrap()));
        let expected = hex::decode("28b52ffd00582900003132333435").unwrap();
        assert_eq!(buf.as_ref(), &expected)
    }
}
