use std::sync::Arc;

use crate::notifications::Message;
use crate::notifications::Notifier;
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
}

impl ZstdEnc {
    #[tracing::instrument(level = "trace", skip(last))]
    #[allow(dead_code)]
    pub fn new(last: bool) -> Self {
        ZstdEnc {
            internal_buf: ZstdEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK)),
            prev_buf: BytesMut::with_capacity(RAW_FRAME_SIZE + CHUNK),
            size_counter: 0,
            chunks: Vec::new(),
            finished: false,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<(bool, bool)> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::ShouldFlush) => return Ok((true, false)),
                    Ok(Message::Finished) => return Ok((false, true)),
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
            self.add_skippable().await;
            self.chunks.push(u8::try_from(self.prev_buf.len() / CHUNK)?);
            buf.put(self.prev_buf.split().freeze());
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
                notifier.send_next_type(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    TransformerType::FooterGenerator,
                    Message::Blocklist(self.chunks.clone()),
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
    let mut frame = hex::decode("542A4D18")?;
    // 4 Bytes (little-endian) for size
    WriteBytesExt::write_u32::<LittleEndian>(&mut frame, size as u32 - 8)?;
    frame.extend(vec![0; size - 8]);
    Ok(Bytes::from(frame))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_zstd_encoder_with_skip() {
        let mut encoder = ZstdEnc::new(false);
        let mut buf = BytesMut::new();
        buf.put(b"12345".as_slice());
        encoder.process_bytes(&mut buf).await.unwrap();
        // Starts with magic zstd header (little-endian)
        assert!(buf.starts_with(&hex::decode("28B52FFD").unwrap()));
        // Expect 65kb size
        assert_eq!(buf.len(), 65536);
        let expected = hex::decode(format!(
            "28b52ffd00582900003132333435502a4d18eaff{}",
            "00".repeat(65516)
        ))
        .unwrap();
        assert_eq!(buf.as_ref(), &expected)
    }

    #[tokio::test]
    async fn test_zstd_encoder_without_skip() {
        let mut encoder = ZstdEnc::new(true);
        let mut buf = BytesMut::new();
        buf.put(b"12345".as_slice());
        encoder.process_bytes(&mut buf).await.unwrap();
        // Starts with magic zstd header (little-endian)
        assert!(buf.starts_with(&hex::decode("28B52FFD").unwrap()));
        // Expect 14b size
        assert_eq!(buf.len(), 14);
        let expected = hex::decode("28b52ffd00582900003132333435").unwrap();
        assert_eq!(buf.as_ref(), &expected)
    }
}
