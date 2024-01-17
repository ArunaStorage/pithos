use crate::notifications::{HashType, Message, Notifier};
use crate::structs::Flag::{
    Compressed, Encrypted, HasBlocklist, HasEncryptionMetadata, HasSemanticMetadata,
};
use crate::structs::{
    BlockList, EncryptionMetadata, EncryptionPacket, EndOfFileMetadata, FileContext,
    SemanticMetadata,
};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use crate::transformers::encrypt::encrypt_chunk;
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::{BufMut, Bytes};
use digest::Digest;
use sha2::Sha256;
use std::sync::Arc;
use tracing::debug;
use tracing::error;

pub struct FooterGenerator {
    hasher: Sha256,
    counter: u64,
    endoffile: EndOfFileMetadata,
    blocklist: Option<Vec<u8>>,
    filectx: Option<FileContext>,
    metadata: Option<(Option<Vec<u8>>, String)>,
    sha1_hash: Option<String>,
    md5_hash: Option<String>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl FooterGenerator {
    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new() -> FooterGenerator {
        debug!("new FooterGenerator");
        FooterGenerator {
            hasher: Sha256::new(),
            counter: 0,
            endoffile: EndOfFileMetadata::init(),
            blocklist: None,
            filectx: None,
            metadata: None,
            sha1_hash: None,
            md5_hash: None,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) | Ok(Message::ShouldFlush) => return Ok(true),
                    Ok(Message::FileContext(ctx)) => {
                        if ctx.encryption_key.is_some() {
                            self.endoffile.set_flag(Encrypted);
                            self.endoffile.set_flag(HasEncryptionMetadata);
                        }
                        self.filectx = Some(ctx);
                    }
                    Ok(Message::Compression(is_compressed)) => {
                        if is_compressed {
                            self.endoffile.set_flag(Compressed);
                        } else {
                            self.endoffile.unset_flag(Compressed);
                        }
                    }
                    Ok(Message::Blocklist(bl)) => {
                        self.blocklist = Some(bl);
                        self.endoffile.set_flag(HasBlocklist);
                    }
                    Ok(Message::Metadata(md)) => {
                        self.metadata = Some(md);
                        self.endoffile.set_flag(HasSemanticMetadata);
                    }
                    Ok(Message::Hash((hash_type, hash))) => match hash_type {
                        HashType::Md5 => self.md5_hash = Some(hash),
                        HashType::Sha1 => self.sha1_hash = Some(hash),
                        _ => {}
                    },
                    Ok(_) => {}
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Closed) => {
                        error!("Message receiver closed");
                        return Err(anyhow!("Message receiver closed"));
                    }
                }
            }
        }
        Ok(false)
    }

    pub fn finalize_size(&mut self) {

    }
}

#[async_trait::async_trait]
impl Transformer for FooterGenerator {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::FooterGenerator, sx)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        // Update overall hash & size counter
        self.hasher.update(buf.as_ref());
        self.counter += buf.len() as u64;

        if let Ok(finished) = self.process_messages() {
            if finished {
                if let Some(file_ctx) = &self.filectx {
                    // (optional) Metadata (optional) encrypted
                    if let Some((encryption_key, metadata)) = &self.metadata {
                        let encoded_metadata: Vec<u8> =
                            SemanticMetadata::new(metadata.clone()).into();
                        let metadata_bytes = if let Some(key) =
                            encryption_key.clone().or(file_ctx.encryption_key.clone())
                        {
                            encrypt_chunk(&encoded_metadata, &[], key.as_slice(), false)?
                        } else {
                            Bytes::from(encoded_metadata)
                        };
                        self.endoffile.semantic_len = Some(metadata_bytes.len() as u64);
                        self.hasher.update(&metadata_bytes);
                        self.counter += metadata_bytes.len() as u64;
                        buf.put(metadata_bytes);
                    }

                    // (optional) Blocklist
                    if let Some(blocklist) = &self.blocklist {
                        let encoded_blocklist: Vec<u8> = BlockList::new(blocklist.clone()).into();
                        self.endoffile.blocklist_len = Some(encoded_blocklist.len() as u64);
                        self.hasher.update(encoded_blocklist.as_slice());
                        self.counter += encoded_blocklist.len() as u64;
                        buf.put(encoded_blocklist.as_slice());
                    }

                    // (optional) Encryption
                    if let Some(key) = &file_ctx.encryption_key {
                        if let Some(pk) = &file_ctx.owners_pubkey {
                            let mut encryption_metadata =
                                EncryptionMetadata::new(vec![EncryptionPacket::new(
                                    vec![key.as_slice().try_into()?],
                                    *pk,
                                )]);
                            encryption_metadata.encrypt_all(None)?;
                            let encryption_data_bytes: Vec<u8> = encryption_metadata.try_into()?;
                            self.hasher.update(encryption_data_bytes.as_slice());
                            self.endoffile.encryption_len = Some(encryption_data_bytes.len() as u64);
                            self.counter += encryption_data_bytes.len() as u64;
                            buf.put(encryption_data_bytes.as_slice());
                        }
                    }

                    // Technical Metadata
                    self.endoffile.update_with_file_ctx(file_ctx)?;
                    let encoded_technical_metadata: Vec<u8> = self.endoffile.clone().try_into()?;
                    self.hasher.update(encoded_technical_metadata.as_slice());
                    self.endoffile.disk_hash_sha256 =
                        self.hasher.finalize_reset().as_slice().try_into()?;
                    self.endoffile.finalize();
                    buf.put(encoded_technical_metadata.as_slice());

                    // Reset counter & hasher
                    self.counter = 0;
                    self.hasher.reset();

                    if let Some(notifier) = &self.notifier {
                        notifier.send_next(
                            self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                            Message::Finished,
                        )?;
                    }
                } else {
                    return Err(anyhow!("Missing file context"));
                }
            }
        } else {
            return Err(anyhow!("Error processing messages"));
        };

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}
