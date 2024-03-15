use std::sync::Arc;

use crate::helpers::notifications::Message;
use crate::helpers::notifications::Notifier;
use crate::transformer::Sink;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::{anyhow, Result};
use async_channel::Receiver;
use async_channel::Sender;
use async_channel::TryRecvError;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncWrite, BufWriter};
use tracing::debug;
use tracing::error;

pub struct WriterSink<W: AsyncWrite + Unpin> {
    writer: BufWriter<W>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl<W: AsyncWrite + Unpin + Send> Sink for WriterSink<W> {}

impl<W: AsyncWrite + Unpin> WriterSink<W> {
    #[tracing::instrument(level = "trace", skip(writer))]
    pub fn new(writer: BufWriter<W>) -> Self {
        Self {
            writer,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    async fn process_messages(&mut self) -> Result<()> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => {
                        if let Some(notifier) = &self.notifier {
                            self.writer.shutdown().await?;
                            notifier.send_read_writer(Message::Completed)?;
                            debug!("WriteSink completed");
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
impl<W: AsyncWrite + Unpin + Send> Transformer for WriterSink<W> {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::Sink, sx)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        if !buf.is_empty() {
            while !buf.is_empty() {
                self.writer.write_buf(buf).await?;
            }
        } else {
            self.writer.flush().await?;
            self.process_messages().await?;
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
