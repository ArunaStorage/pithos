use crate::notifications::Message;
use anyhow::Result;

// Marker trait to signal that this Transformer can be a "final" destination for data
pub trait IsSink {}

pub trait Sink: Transformer + IsSink + Send {}

pub enum Category {
    ZstdComp,
    ZstdDecomp,
    ChaChaEnc,
    ChaChaDec,
    Filter,
    Footer,
    Probe,
}

#[async_trait::async_trait]
pub trait Notifier {
    async fn notify(&self, target: u64, message: Message) -> Result<Message>;
    async fn get_next_id_of_type(&self, target: Category) -> Option<u64>;
}

#[async_trait::async_trait]
pub trait ReadWriter {
    async fn process(&mut self) -> Result<()>;
}

#[async_trait::async_trait]
pub trait Transformer {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool>;
    async fn notify(&mut self, message: Message) -> Result<Message> {
        Ok(Message::default())
    }
    fn set_id(&mut self, id: u64);
    fn get_id(&self) -> u64;
    fn add_root<T: Notifier>(&mut self, notifier: dyn Notifier) {}
}
