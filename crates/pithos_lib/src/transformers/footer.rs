use crate::helpers::notifications::{Message, Notifier};
use crate::helpers::structs::FileContext;
use crate::pithos::structs::{DirContextHeader, EncryptionTarget, EndOfFileMetadata, FileContextHeader, TableOfContents};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender};
use digest::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

pub struct FooterGenerator {
    hasher: Sha256,
    counter: u64,
    directories: Vec<DirContextHeader>,
    files: Vec<FileContextHeader>,
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
            encryption_keys: HashMap::new(),
            sha256_hash: None,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    pub fn new_with_ctx(ctx: FileContext) -> Result<FooterGenerator> {
        let map = if let Some(readers_key) = ctx.owners_pubkey {
            if let Some(enc_key) = ctx.encryption_key {
                HashMap::from([(
                    readers_key,
                    vec![enc_key
                        .try_into()
                        .map_err(|_| anyhow!("Vec<u8> to [u8;32] conversion failed"))?],
                )])
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        Ok(FooterGenerator {
            hasher: Sha256::new(),
            counter: 0,
            encryption_keys: map,
            notifier: None,
            msg_receiver: None,
            idx: None,
        })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            // loop {
            //     match rx.try_recv() {
            //         Ok(Message::Finished) | Ok(Message::ShouldFlush) => return Ok(true),
            //         Ok(Message::FileContext(ctx)) => {
            //             todo!();
            //             if ctx.encryption_key.is_some() {
            //                 self.eof_metadata.set_flag(Encrypted);
            //                 self.eof_metadata.set_flag(HasEncryptionMetadata);
            //             }

            //             //self.filectx = Some(ctx);
            //         }
            //         Ok(Message::Compression(is_compressed)) => {
            //             if is_compressed {
            //                 self.eof_metadata.set_flag(Compressed);
            //             } else {
            //                 self.eof_metadata.unset_flag(Compressed);
            //             }
            //         }
            //         Ok(Message::Metadata(md)) => {
            //             debug!("Received metadata");
            //             self.metadata = Some(md);
            //             self.eof_metadata.set_flag(HasSemanticMetadata);
            //         }
            //         Ok(Message::Hash((hash_type, hash))) => match hash_type {
            //             HashType::Md5 => self.md5_hash = Some(hash),
            //             HashType::Sha1 => self.sha1_hash = Some(hash),
            //             _ => {}
            //         },
            //         Ok(_) => {}
            //         Err(TryRecvError::Empty) => {
            //             break;
            //         }
            //         Err(TryRecvError::Closed) => {
            //             error!("Message receiver closed");
            //             return Err(anyhow!("Message receiver closed"));
            //         }
            //     }
            // }
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

                // Write
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
