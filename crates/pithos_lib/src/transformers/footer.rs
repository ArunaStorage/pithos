use crate::helpers::notifications::{DirOrFileIdx, Message, Notifier};
use crate::helpers::structs::{EncryptionKey, FileContext};
use crate::pithos::structs::{DirContextHeader, EncryptionTarget, FileContextHeader, PithosRange};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender, TryRecvError};
use digest::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error};

pub struct FooterGenerator {
    hasher: Sha256,
    counter: u64,
    directories: Vec<DirContextHeader>,
    files: Vec<FileContextHeader>,
    path_table: HashMap<String, DirOrFileIdx>,
    unassigned_symlinks: Vec<FileContext>,
    encryption_keys: HashMap<[u8; 32], Vec<([u8; 32], EncryptionTarget)>>, // <Reader PubKey, List of encryption keys>
    sha256_hash: Option<String>,
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
            directories: Vec::new(),
            files: Vec::new(),
            path_table: HashMap::default(),
            unassigned_symlinks: vec![],
            encryption_keys: HashMap::new(),
            sha256_hash: None,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    pub fn new_with_ctx(ctx: FileContext) -> Result<FooterGenerator> {
        let map = if let Some(readers_key) = ctx.owners_pubkey {
            match ctx.encryption_key {
                EncryptionKey::None => HashMap::new(),
                EncryptionKey::Same(enc_key) => HashMap::from([(
                    readers_key,
                    vec![(
                        enc_key
                            .try_into()
                            .map_err(|_| anyhow!("Vec<u8> to [u8;32] conversion failed"))?,
                        EncryptionTarget::FileDataAndMetadata(PithosRange::All),
                    )],
                )]),
                EncryptionKey::DataOnly(enc_key) => HashMap::from([(
                    readers_key,
                    vec![(
                        enc_key
                            .try_into()
                            .map_err(|_| anyhow!("Vec<u8> to [u8;32] conversion failed"))?,
                        EncryptionTarget::FileData(PithosRange::All),
                    )],
                )]),
                EncryptionKey::Individual((data, meta)) => HashMap::from([(
                    readers_key,
                    vec![
                        (
                            data.try_into()
                                .map_err(|_| anyhow!("Vec<u8> to [u8;32] conversion failed"))?,
                            EncryptionTarget::FileData(PithosRange::All),
                        ),
                        (
                            meta.try_into()
                                .map_err(|_| anyhow!("Vec<u8> to [u8;32] conversion failed"))?,
                            EncryptionTarget::FileMetadata(PithosRange::All),
                        ),
                    ],
                )]),
            }
        } else {
            HashMap::new()
        };

        Ok(FooterGenerator {
            hasher: Sha256::new(),
            counter: 0,
            directories: Vec::new(),
            files: Vec::new(),
            path_table: HashMap::default(),
            unassigned_symlinks: vec![],
            encryption_keys: map,
            sha256_hash: None,
            notifier: None,
            msg_receiver: None,
            idx: None,
        })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => return Ok(true),
                    Ok(Message::FileContext(ctx)) => {
                        if ctx.is_dir {
                            self.directories.push(ctx.into())
                        } else if ctx.symlink_target.is_none() {
                            self.files.push(ctx.try_into()?)
                        } else {
                            // Modify FileContextHeader --> Add SymlinkContextHeader
                        }
                    }
                    Ok(Message::CompressionInfo(compression_info)) => {
                        todo!()
                    }
                    Ok(Message::Hash((hash_type, hash, idx))) => {
                        todo!()
                    }
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
                // Write TableOfContents

                // Write Encryption Metadata

                // Write EndOfFileMetadata
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
