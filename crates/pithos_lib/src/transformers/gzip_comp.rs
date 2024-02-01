use crate::helpers::notifications::Message;
use crate::helpers::notifications::Notifier;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::{anyhow, Result};
use async_channel::Receiver;
use async_channel::Sender;
use async_channel::TryRecvError;
use async_compression::tokio::write::GzipEncoder;
use bytes::BufMut;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use tracing::error;

const RAW_FRAME_SIZE: usize = 5_242_880;

pub struct GzipEnc {
    internal_buf: GzipEncoder<Vec<u8>>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    size_counter: usize,
}

impl GzipEnc {
    #[tracing::instrument(level = "trace", skip())]
    #[allow(dead_code)]
    pub fn new() -> Self {
        GzipEnc {
            internal_buf: GzipEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE)),
            idx: None,
            msg_receiver: None,
            notifier: None,
            size_counter: 0,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) | Ok(Message::ShouldFlush) => return Ok(true),
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
        Ok(false)
    }
}

impl Default for GzipEnc {
    #[tracing::instrument(level = "trace", skip())]
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transformer for GzipEnc {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::GzipCompressor, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        self.size_counter += buf.len();
        self.internal_buf.write_all_buf(buf).await?;

        let Ok(finished) = self.process_messages() else {
            return Err(anyhow!("GzipEnc: Error processing messages"));
        };
        if finished && self.size_counter != 0 {
            debug!("finished");
            self.internal_buf.shutdown().await?;
            buf.put(self.internal_buf.get_ref().as_slice());
            self.size_counter = 0;
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
            }
            return Ok(());
        }

        // Create a new frame if buf would increase size_counter to more than RAW_FRAME_SIZE
        if self.size_counter > RAW_FRAME_SIZE {
            debug!(?self.size_counter, "new_frame");
            self.internal_buf.flush().await?;
            debug!(buf_len = ?self.internal_buf.get_ref().len());
            buf.put(self.internal_buf.get_ref().as_slice());
            self.internal_buf.get_mut().clear();
            self.size_counter = 0;
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}
