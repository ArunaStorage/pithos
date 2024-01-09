use crate::transformer::{Sink, Transformer, TransformerType};
use anyhow::Result;
use hyper::body::Sender;
use hyper::Body;

pub struct HyperSink {
    sender: Sender,
}

impl Sink for HyperSink {}

impl HyperSink {
    #[tracing::instrument(level = "trace", skip())]
    pub fn new() -> (Self, Body) {
        let (sender, body) = hyper::Body::channel();
        (Self { sender }, body)
    }
}

#[async_trait::async_trait]
impl Transformer for HyperSink {
    #[tracing::instrument(level = "trace", skip(self, buf, finished))]
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        _: bool,
    ) -> Result<bool> {
        self.sender.send_data(buf.split().freeze()).await?;
        if finished {
            return Ok(true);
        }
        Ok(false)
    }
    #[tracing::instrument(level = "trace", skip(self))]
    #[inline]
    fn get_type(&self) -> TransformerType {
        TransformerType::HyperSink
    }
}
