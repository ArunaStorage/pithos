use crate::transformer::{Sink, Transformer};
use anyhow::Result;
use hyper::body::Sender;
use hyper::Body;

pub struct HyperSink {
    sender: Sender,
    id: usize,
}

impl Sink for HyperSink {}

impl HyperSink {
    pub fn new() -> (Self, Body) {
        let (sender, body) = hyper::Body::channel();
        (Self { sender, id: 0 }, body)
    }
}
impl<HyperSink: Transformer + Sink + Send> Sink for HyperSink {}

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

    fn set_id(&mut self, id: u64) {
        self.id = id
    }
    fn get_id(&self) -> u64 {
        self.id
    }
}
