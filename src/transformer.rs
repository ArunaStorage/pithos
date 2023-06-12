use crate::notifications::{Message, Response};
use anyhow::Result;
use async_channel::Sender;

// Marker trait to signal that this Transformer can be a "final" destination for data
pub trait Sink: Transformer {}

#[async_trait::async_trait]
pub trait ReadWriter {
    async fn process(&mut self) -> Result<()>;
    async fn announce_all(&mut self, message: Message) -> Result<()>;
}

#[async_trait::async_trait]
pub trait Transformer {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool>;
    async fn notify(&mut self, message: Message) -> Result<Response> {
        Ok(Response::Ok)
    }
    fn add_sender(&mut self, s: Sender<Message>) {}
}
