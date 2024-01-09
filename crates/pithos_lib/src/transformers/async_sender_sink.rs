use crate::transformer::Sink;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::Result;
use async_channel::Sender;
use tracing::debug;
use tracing::error;

pub struct AsyncSenderSink {
    sender: Sender<Result<bytes::Bytes>>,
}

impl Sink for AsyncSenderSink {}

impl AsyncSenderSink {
    #[tracing::instrument(level = "trace", skip(sender))]
    pub fn new(sender: Sender<Result<bytes::Bytes>>) -> Self {
        Self { sender }
    }
}

#[async_trait::async_trait]
impl Transformer for AsyncSenderSink {
    #[tracing::instrument(level = "trace", skip(self, buf, finished))]
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        _: bool,
    ) -> Result<bool> {
        if !self.sender.is_closed() {
            self.sender.send(Ok(buf.split().freeze())).await?;
        } else if !buf.is_empty() {
            error!(?buf, "Output closed with remaining bytes in buf");
            return Err(anyhow!("Output closed with remaining bytes in buf"));
        }
        if buf.is_empty() && finished {
            debug!("finished");
            return Ok(true);
        }
        Ok(false)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    #[inline]
    fn get_type(&self) -> TransformerType {
        TransformerType::AsyncSenderSink
    }
}
