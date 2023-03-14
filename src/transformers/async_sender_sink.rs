use crate::transformer::AddTransformer;
use crate::transformer::Notifications;
use crate::transformer::Sink;
use crate::transformer::Transformer;
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

impl AddTransformer<'_> for AsyncSenderSink {
    fn add_transformer<'a>(self: &mut AsyncSenderSink, _t: Box<dyn Transformer + Send + 'a>) {}
}

#[async_trait::async_trait]
impl Transformer for AsyncSenderSink {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        self.sender.send(Ok(buf.to_owned())).await?;
        if buf.len() != 0 && finished {
            return Ok(true);
        }
        Ok(false)
    }
    async fn notify(&mut self, _notes: &mut Vec<Notifications>) -> Result<()> {
        Ok(())
    }
}
