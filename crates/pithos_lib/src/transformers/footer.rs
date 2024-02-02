use crate::helpers::notifications::{DirOrFileIdx, HashType, Message, Notifier};
use crate::helpers::structs::{EncryptionKey, FileContext};
use crate::pithos::structs::{
    DirContextHeader, DirContextVariants, EncryptionTarget, FileContextHeader, FileContextVariants,
    Hashes, PithosRange, SymlinkContextHeader, TableOfContents,
};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use anyhow::{anyhow, bail};
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
                        EncryptionTarget::FileDataAndMetadata(PithosRange::Index(ctx.idx as u64)),
                    )],
                )]),
                EncryptionKey::DataOnly(enc_key) => HashMap::from([(
                    readers_key,
                    vec![(
                        enc_key
                            .try_into()
                            .map_err(|_| anyhow!("Vec<u8> to [u8;32] conversion failed"))?,
                        EncryptionTarget::FileData(PithosRange::Index(ctx.idx as u64)),
                    )],
                )]),
                EncryptionKey::Individual((data, meta)) => HashMap::from([(
                    readers_key,
                    vec![
                        (
                            data.try_into()
                                .map_err(|_| anyhow!("Vec<u8> to [u8;32] conversion failed"))?,
                            EncryptionTarget::FileData(PithosRange::Index(ctx.idx as u64)),
                        ),
                        (
                            meta.try_into()
                                .map_err(|_| anyhow!("Vec<u8> to [u8;32] conversion failed"))?,
                            EncryptionTarget::FileMetadata(PithosRange::Index(ctx.idx as u64)),
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
                            self.path_table
                                .insert(ctx.file_path, DirOrFileIdx::Dir(ctx.idx));
                            self.directories.push(ctx.into())
                        } else if ctx.symlink_target.is_none() {
                            self.path_table
                                .insert(ctx.file_path, DirOrFileIdx::File(ctx.idx));
                            self.files.push(ctx.try_into()?)
                        } else {
                            if let Some(idx) = self
                                .path_table
                                .get(&ctx.symlink_target.ok_or_else(|| anyhow!(""))?)
                            {
                                match idx {
                                    DirOrFileIdx::File(idx) => {
                                        let mut_ctx =
                                            self.files.get_mut(*idx).ok_or_else(|| {
                                                anyhow!("FileContextHeader does not exist")
                                            })?;
                                        let symlink_ctx = SymlinkContextHeader {
                                            file_path: ctx.file_path,
                                            file_info: ctx.try_into()?,
                                        };
                                        if let Some(symlinks) = mut_ctx.symlinks.as_mut() {
                                            symlinks.push(symlink_ctx)
                                        } else {
                                            mut_ctx.symlinks = Some(vec![symlink_ctx])
                                        }
                                    }
                                    DirOrFileIdx::Dir(idx) => {
                                        let mut_ctx =
                                            self.directories.get_mut(*idx).ok_or_else(|| {
                                                anyhow!("DirContextHeader does not exist")
                                            })?;
                                        let symlink_ctx = SymlinkContextHeader {
                                            file_path: ctx.file_path,
                                            file_info: ctx.try_into()?,
                                        };
                                        if let Some(symlinks) = mut_ctx.symlinks.as_mut() {
                                            symlinks.push(symlink_ctx)
                                        } else {
                                            mut_ctx.symlinks = Some(vec![symlink_ctx])
                                        }
                                    }
                                }
                            } else {
                                self.unassigned_symlinks.push(ctx)
                            }
                        }
                    }
                    Ok(Message::CompressionInfo(compression_info)) => {
                        let mut_ctx = self
                            .files
                            .get_mut(compression_info.idx)
                            .ok_or_else(|| anyhow!("FileContextHeader does not exist"))?;
                        mut_ctx.compressed = compression_info.compression;
                        if mut_ctx.disk_size == 0 {
                            mut_ctx.disk_size = compression_info.size;
                        } else if mut_ctx.disk_size != compression_info.size {
                            bail!("Compression size does not match file disk size");
                        }
                        mut_ctx.index_list = compression_info.chunk_infos;
                    }
                    Ok(Message::Hash((hash_type, hash, idx))) => {
                        if let Some(idx) = idx {
                            let mut_ctx = self
                                .files
                                .get_mut(idx)
                                .ok_or_else(|| anyhow!("FileContextHeader does not exist"))?;
                            match hash_type {
                                HashType::Sha256 => {
                                    let sha256_bytes: [u8; 32] = hash.try_into().map_err(|_| {
                                        anyhow!("Provided SHA256 has invalid length")
                                    })?;
                                    if let Some(Hashes {
                                        sha256: Some(hash), ..
                                    }) = mut_ctx.hashes
                                    {
                                        if hash != sha256_bytes {
                                            bail!("SHA256 hash mismatch");
                                        }
                                    } else if let Some(Hashes { sha256: _None, md5 }) =
                                        mut_ctx.hashes
                                    {
                                        mut_ctx.hashes = Some(Hashes {
                                            sha256: Some(sha256_bytes),
                                            md5,
                                        });
                                    } else {
                                        mut_ctx.hashes = Some(Hashes {
                                            sha256: Some(sha256_bytes),
                                            md5: None,
                                        });
                                    }
                                }
                                HashType::Md5 => {
                                    let md5_bytes: [u8; 16] = hash
                                        .try_into()
                                        .map_err(|_| anyhow!("Provided MD5 has invalid length"))?;
                                    if let Some(Hashes {
                                        md5: Some(hash), ..
                                    }) = mut_ctx.hashes
                                    {
                                        if hash != md5_bytes {
                                            bail!("SHA256 hash mismatch");
                                        }
                                    } else if let Some(Hashes { md5: _None, sha256 }) =
                                        mut_ctx.hashes
                                    {
                                        mut_ctx.hashes = Some(Hashes {
                                            sha256,
                                            md5: Some(md5_bytes),
                                        });
                                    } else {
                                        mut_ctx.hashes = Some(Hashes {
                                            sha256: None,
                                            md5: Some(md5_bytes),
                                        });
                                    }
                                }
                                HashType::Other(_) => {
                                    bail!("Other hashes currently not supported")
                                }
                            };
                        }
                    }
                    Ok(Message::SizeInfo(_)) => {
                        // Sum all FileContext sizes
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
            //TODO: Evaluate keys map

            if finished {
                // Write TableOfContents
                let mut toc = TableOfContents::new();
                toc.directories = self
                    .directories
                    .iter()
                    .map(|ctx| DirContextVariants::DirDecrypted(ctx))
                    .collect();
                toc.files = self
                    .files
                    .iter()
                    .map(|ctx| FileContextVariants::FileDecrypted(ctx))
                    .collect();

                toc.finalize(todo!());

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
