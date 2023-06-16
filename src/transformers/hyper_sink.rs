use crate::transformer::{Sink, Transformer, TransformerType};
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

#[async_trait::async_trait]
impl Transformer for HyperSink {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        if !buf.is_empty() {
            self.sender.send_data(buf.split().freeze()).await?;
        } else if finished {
            self.sender.send_data(buf.split().freeze()).await?;
            return Ok(true);
        }
        Ok(false)
    }
    #[inline]
    fn get_type(&self) -> TransformerType {
        TransformerType::HyperSink
    }
}
