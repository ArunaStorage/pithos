use crate::notifications::Notifications;
use crate::transformer::AddTransformer;
use crate::transformer::Sink;
use crate::transformer::Transformer;
use anyhow::Result;
use hyper::body::Sender;
use hyper::Body;

pub struct HyperSink {
    sender: Sender,
}

impl Sink for HyperSink {}

impl HyperSink {
    pub fn new() -> (Self, Body) {
        let (sender, body) = hyper::Body::channel();
        (Self { sender }, body)
    }
}

impl AddTransformer<'_> for HyperSink {
    fn add_transformer<'a>(self: &mut HyperSink, _t: Box<dyn Transformer + Send + 'a>) {}
}

#[async_trait::async_trait]
impl Transformer for HyperSink {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        if !buf.is_empty() {
            self.sender.send_data(buf.to_owned()).await?;
        } else if finished {
            self.sender.send_data(buf.to_owned()).await?;
            return Ok(true);
        }
        Ok(false)
    }
    async fn notify(&mut self, _notes: &mut Vec<Notifications>) -> Result<()> {
        Ok(())
    }
}
