use crate::notifications::Message;
use crate::transformer::Sink;
use crate::transformer::Transformer;
use anyhow::Result;
use async_channel::Sender;

pub struct AsyncSenderSink {
    sender: Sender<Result<bytes::Bytes>>,
    id: u64,
}

impl Sink for AsyncSenderSink {}

impl AsyncSenderSink {
    pub fn new(sender: Sender<Result<bytes::Bytes>>) -> Self {
        Self { sender, id: 0 }
    }
}

#[async_trait::async_trait]
impl Transformer for AsyncSenderSink {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        if !self.sender.is_closed() {
            self.sender.send(Ok(buf.to_owned())).await?;
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
    async fn notify(&mut self, message: Message) -> Result<Message> {
        Ok(Message::default())
    }

    fn set_id(&mut self, id: u64) {
        self.id = id
    }

    fn get_id(&self) -> u64 {
        self.id
    }
}
