use std::sync::Arc;

use crate::notifications::{Message, Notifier};
use crate::transformer::{Transformer, TransformerType};
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender, TryRecvError};
use tracing::{debug, error};

pub struct SizeProbe {
    size_counter: u64,
    size_sender: Sender<u64>,
    notifier: Option<Arc<Notifier>>,
    idx: Option<usize>,
}

impl SizeProbe {
    #[tracing::instrument(level = "trace", skip())]
    #[allow(dead_code)]
    pub fn new() -> (SizeProbe, Receiver<u64>) {
        let (size_sender, size_receiver) = async_channel::bounded(1);

        (
            SizeProbe {
                size_counter: 0,
                notifier: None,
                idx: None,
                size_sender,
            },
            size_receiver,
        )
    }

    #[tracing::instrument(level = "trace", skip(self))]
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
impl Transformer for SizeProbe {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::SizeProbe, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        self.size_counter += buf.len() as u64;

        if buf.is_empty() {
            let Ok(finished) = self.process_messages() else {
                return Err(anyhow!("HashingTransformer: Error processing messages"));
            };

            if finished {
                if let Some(notifier) = &self.notifier {
                    notifier.send_read_writer(Message::SizeInfo(self.size_counter))?;
                    notifier.send_next(
                        self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                        Message::Finished,
                    )
                }
            }
            return Ok(());
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
