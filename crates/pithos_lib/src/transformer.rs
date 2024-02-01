use crate::helpers::notifications::{Message, Notifier};
use anyhow::Result;
use async_channel::{Receiver, Sender};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TransformerType {
    Unspecified,
    ReadWriter,
    All,
    AsyncSenderSink,
    ZstdCompressor,
    GzipCompressor,
    ZstdDecompressor,
    ChaCha20Encrypt,
    ChaCha20Decrypt,
    Filter,
    FooterGenerator,
    HyperSink,
    SizeProbe,
    TarEncoder,
    TarDecoder,
    Sink,
    Hashing,
    ZipEncoder,
}

// Marker trait to signal that this Transformer can be a "final" destination for data
pub trait Sink: Transformer {}

#[async_trait::async_trait]
pub trait ReadWriter {
    async fn process(&mut self) -> Result<()>;
    async fn announce_all(&mut self, message: Message) -> Result<()>;
    async fn add_message_receiver(&mut self, rx: Receiver<Message>) -> Result<()>;
}

#[async_trait::async_trait]
pub trait Transformer {
    #[allow(unused_variables)]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>);

    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()>;

    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()>;
}
