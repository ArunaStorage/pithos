use crate::notifications::{HashType, Message, Notifier};
use crate::structs::Flag::{
    Compressed, Encrypted, HasBlockList, HasEncryptionMetadata, HasSemanticMetadata,
};
use crate::structs::{BlockList, EncryptionMetadata, EncryptionPacket, EndOfFileMetadata, FileContext, SemanticMetadata, TableOfContents};
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
use std::collections::HashMap;

pub struct FooterGenerator {
    hasher: Sha256,
    counter: u64,
    eof_metadata: EndOfFileMetadata,
    ranges: TableOfContents,
    blocklist: Option<Vec<u8>>,
    encryption_keys: HashMap<[u8; 32], Vec<[u8; 32]>>, // <Reader PubKey, List of encryption keys>
    metadata: Option<(Option<Vec<u8>>, String)>, // (Dedicated encryption key, Semantic metadata)
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
            eof_metadata: EndOfFileMetadata::init(),
            ranges: TableOfContents::new(),
            blocklist: None,
            encryption_keys: HashMap::new(),
            metadata: None,
            sha1_hash: None,
            md5_hash: None,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    pub fn new_with_ctx(ctx: FileContext) -> FooterGenerator {

        let map = if let Some(readers_key) = ctx.owners_pubkey {
            if let Some(enc_key) = ctx.encryption_key {
                HashMap::from([(readers_key, vec![enc_key])])
            }else{
                HashMap::new()
            }
        }else{
            HashMap::new()
        };
        FooterGenerator {
            hasher: Sha256::new(),
            counter: 0,
            eof_metadata: EndOfFileMetadata::init(),
            ranges: TableOfContents::new(),
            blocklist: None,
            encryption_keys: map,
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
                            self.eof_metadata.set_flag(Encrypted);
                            self.eof_metadata.set_flag(HasEncryptionMetadata);
                        }
                        self.filectx = Some(ctx);
                    }
                    Ok(Message::Compression(is_compressed)) => {
                        if is_compressed {
                            self.eof_metadata.set_flag(Compressed);
                        } else {
                            self.eof_metadata.unset_flag(Compressed);
                        }
                    }
                    Ok(Message::Blocklist(bl)) => {
                        self.blocklist = Some(bl);
                        self.eof_metadata.set_flag(HasBlockList);
                    }
                    Ok(Message::Metadata(md)) => {
                        debug!("Received metadata");
                        self.metadata = Some(md);
                        self.eof_metadata.set_flag(HasSemanticMetadata);
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
                if let Some((encryption_key, metadata)) = &self.metadata {
                    let encoded_metadata: Vec<u8> =
                        SemanticMetadata::new(metadata.clone()).try_into()?;
                    let metadata_bytes = if let Some(key) =
                        encryption_key.clone().or(file_ctx.encryption_key.clone())
                    {
                        self.eof_metadata
                            .set_flag(crate::structs::Flag::SemanticMetadataEncrypted);
                        encrypt_chunk(&encoded_metadata, &[], key.as_slice(), false)?
                    } else {
                        Bytes::from(encoded_metadata)
                    };
                    self.eof_metadata.semantic_len = Some(metadata_bytes.len() as u64);
                    self.hasher.update(&metadata_bytes);
                    self.counter += metadata_bytes.len() as u64;
                    buf.put(metadata_bytes);
                }

                // (optional) Blocklist
                if let Some(blocklist) = &self.blocklist {
                    let encoded_blocklist: Vec<u8> =
                        BlockList::new(blocklist.clone()).try_into()?;
                    self.eof_metadata.blocklist_len = Some(encoded_blocklist.len() as u64);
                    self.hasher.update(encoded_blocklist.as_slice());
                    self.counter += encoded_blocklist.len() as u64;
                    buf.put(encoded_blocklist.as_slice());
                }

                // (optional) Encryption
                if let Some(key) = &file_ctx.encryption_key {
                    if let Some(pk) = &file_ctx.owners_pubkey {
                        debug!(?pk, "Create encryption metadata");
                        let mut encryption_metadata =
                            EncryptionMetadata::new(vec![EncryptionPacket::new(
                                vec![key.as_slice().try_into()?],
                                *pk,
                            )]);
                        encryption_metadata.encrypt_all(None)?;
                        debug!(?encryption_metadata);
                        let encryption_data_bytes: Vec<u8> = encryption_metadata.try_into()?;
                        debug!(encryption_bytes_len = encryption_data_bytes.len());
                        self.hasher.update(encryption_data_bytes.as_slice());
                        self.eof_metadata.encryption_len =
                            Some(encryption_data_bytes.len() as u64);
                        self.counter += encryption_data_bytes.len() as u64;
                        buf.put(encryption_data_bytes.as_slice());
                    }
                }

                // Technical Metadata
                self.eof_metadata.finalize();
                self.eof_metadata.disk_file_size = self.counter + self.eof_metadata.eof_metadata_len;

                let encoded_technical_metadata: Vec<u8> = self.eof_metadata.clone().try_into()?;
                self.hasher.update(encoded_technical_metadata.as_slice());
                self.eof_metadata.disk_hash_sha256 =
                    self.hasher.finalize_reset().as_slice().try_into()?;

                let final_data: Vec<u8> = self.eof_metadata.clone().try_into()?;
                buf.put(final_data.as_slice());

                // Reset counter & hasher
                self.counter = 0;
                self.hasher.reset();

                if let Some(notifier) = &self.notifier {
                    notifier.send_next(
                        self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                        Message::Finished,
                    )?;
                }
                self.filectx = None;
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
