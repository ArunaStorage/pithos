use crate::notifications::{Message, Response};
use anyhow::Result;
use async_channel::{Receiver, Sender};

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
    WriterSink,
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
    pub skip_decompression: bool,
    // Should this file be skipped by decryptors
    pub skip_decryption: bool,
    // Encryption key
    pub encryption_key: Option<Vec<u8>>,
    // Is this file a directory
    pub is_dir: bool,
    // Is this file a symlink
    pub is_symlink: bool,
}

impl FileContext {
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
    async fn add_file_context_receiver(&mut self, rx: Receiver<(FileContext, bool)>) -> Result<()>;
}

#[async_trait::async_trait]
pub trait Transformer {
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        should_flush: bool,
    ) -> Result<bool>;
    #[allow(unused_variables)]
    async fn notify(&mut self, message: &Message) -> Result<Response> {
        Ok(Response::Ok)
    }
    #[allow(unused_variables)]
    fn add_sender(&mut self, s: Sender<Message>) {}
    #[allow(unused_variables)]
    fn get_type(&self) -> TransformerType {
        TransformerType::Unspecified
    }
}
