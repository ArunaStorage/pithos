use crate::notifications::{Message, Notifier};
use crate::transformer::{Sink, Transformer, TransformerType};
use anyhow::{anyhow, Result};
use async_channel::{Receiver, Sender as AsyncSender, TryRecvError};
use hyper::body::Sender;
use hyper::Body;
use std::sync::Arc;
use tracing::{debug, error};

pub struct HyperSink {
    sender: Sender,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl Sink for HyperSink {}

impl HyperSink {
    #[tracing::instrument(level = "trace", skip())]
    pub fn new() -> (Self, Body) {
        let (sender, body) = hyper::Body::channel();
        (
            Self {
                sender,
                notifier: None,
                msg_receiver: None,
                idx: None,
            },
            body,
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
impl Transformer for HyperSink {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, AsyncSender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::HyperSink, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        self.sender.send_data(buf.split().freeze()).await?;
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
