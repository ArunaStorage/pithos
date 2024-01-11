use crate::notifications::{Message, Notifier};
use crate::transformer::Sink;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender, TryRecvError};
use std::sync::Arc;
use tracing::debug;
use tracing::error;

pub struct AsyncSenderSink {
    sender: Sender<Result<bytes::Bytes>>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl Sink for AsyncSenderSink {}

impl AsyncSenderSink {
    #[tracing::instrument(level = "trace", skip(sender))]
    pub fn new(sender: Sender<Result<bytes::Bytes>>) -> Self {
        Self {
            sender,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    fn process_messages(&mut self) -> Result<()> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => {
                        if let Some(notifier) = &self.notifier {
                            notifier.send_read_writer(Message::Finished)?;
                        }
                        debug!("finished");
                        break;
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
        Ok(())
    }
}

#[async_trait::async_trait]
impl Transformer for AsyncSenderSink {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::Sink, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        if !self.sender.is_closed() {
            self.sender.send(Ok(buf.split().freeze())).await?;
        } else if !buf.is_empty() {
            error!(?buf, "Output closed with remaining bytes in buf");
            return Err(anyhow!("Output closed with remaining bytes in buf"));
        }
        if buf.is_empty() {
            self.process_messages()?;
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
