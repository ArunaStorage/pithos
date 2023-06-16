use crate::transformer::Sink;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use async_channel::Sender;

pub struct AsyncSenderSink {
    sender: Sender<Result<bytes::Bytes>>,
}

impl Sink for AsyncSenderSink {}

impl AsyncSenderSink {
    pub fn new(sender: Sender<Result<bytes::Bytes>>) -> Self {
        Self { sender }
    }
}

#[async_trait::async_trait]
impl Transformer for AsyncSenderSink {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        if !self.sender.is_closed() {
            self.sender.send(Ok(buf.split().freeze())).await?;
        } else if !buf.is_empty() {
            log::debug!(
                "[AF_ASYNCSINK] Output closed but still {:?} bytes in buffer",
                buf.len()
            )
        }
        if buf.is_empty() && finished {
            return Ok(true);
        }
        Ok(false)
    }

    #[inline]
    fn get_type(&self) -> TransformerType {
        TransformerType::AsyncSenderSink
    }
}
