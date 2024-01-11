use crate::notifications::{Message, Notifier};
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct FileContext {
    // FileName
    pub file_name: String,
    // Input size
    pub input_size: u64,
    // Filesize
    pub file_size: u64,
    // FileSubpath without filename
    pub file_path: Option<String>,
    // UserId
    pub uid: Option<u64>,
    // GroupId
    pub gid: Option<u64>,
    // Octal like mode
    pub mode: Option<u32>,
    // Created at
    pub mtime: Option<u64>,
    // Should this file be skipped by decompressors
    pub compression: bool,
    // Encryption key
    pub encryption_key: Option<Vec<u8>>,
    // Is this file a directory
    pub is_dir: bool,
    // Is this file a symlink
    pub is_symlink: bool,
    // Expected SHA1 hash
    pub expected_sha1: Option<String>,
    // Expected MD5 hash
    pub expected_md5: Option<String>,
}

impl FileContext {
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_path(&self) -> String {
        match &self.file_path {
            Some(p) => p.clone() + "/" + &self.file_name,
            None => self.file_name.clone(),
        }
    }
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
