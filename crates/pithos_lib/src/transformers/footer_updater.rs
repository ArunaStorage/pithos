use crate::helpers::footer_parser::Footer;
use crate::helpers::notifications::{Message, Notifier};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use anyhow::{anyhow, bail};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::BufMut;
use digest::Digest;
use sha2::Sha256;
use std::sync::Arc;
use tracing::error;

pub struct FooterUpdater {
    hasher: Sha256,
    counter: u64,
    additional_pubkeys: Vec<[u8; 32]>,
    old_footer: Option<Footer>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    finished: bool,
}

impl FooterUpdater {
    #[tracing::instrument(level = "trace", skip(pubkeys, footer))]
    #[allow(dead_code)]
    pub fn new(pubkeys: Vec<[u8; 32]>, footer: Footer) -> FooterUpdater {
        FooterUpdater {
            hasher: Sha256::new(),
            counter: 0,
            additional_pubkeys: pubkeys,
            old_footer: Some(footer),
            notifier: None,
            msg_receiver: None,
            idx: None,
            finished: false,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => return Ok(true),
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
impl Transformer for FooterUpdater {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::FooterGenerator, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        // Update overall hash & size counter
        self.hasher.update(buf.as_ref());
        self.counter += buf.len() as u64;
        match self.process_messages() {
            Ok(finished) => {
                if finished && !self.finished {
                    let Some(Footer { mut eof_metadata, encryption_keys, table_of_contents , raw_encryption_packets}) = self.old_footer.take() else {
                        bail!("Missing old footer");
                    };
                    let toc_bytes = borsh::to_vec(&table_of_contents)?;
                    if eof_metadata.toc_len == toc_bytes.len() as u64 {
                        bail!("TableOfContents length mismatch");
                    }

                    // Update full file hash and write TableOfContents
                    self.hasher.update(toc_bytes.as_slice());
                    buf.put(toc_bytes.as_slice());

                    let Some(mut enc_meta) = raw_encryption_packets else {
                        bail!("Missing raw_encryption_packets");
                    };
                    let Some(keys) = encryption_keys else {
                        bail!("Missing encryption_keys");
                    };
                    for key in self.additional_pubkeys.iter() {
                        enc_meta.add_packet(keys.encrypt(*key, None)?);
                    }
                    let enc_meta_bytes = borsh::to_vec(&enc_meta)?;
                    eof_metadata.encryption_len = enc_meta_bytes.len() as u64;
                    self.hasher.update(enc_meta_bytes.as_slice());
                    buf.put(enc_meta_bytes.as_slice());

                    // Write EndOfFileMetadata
                    eof_metadata.disk_file_size = self.counter;
                    let mut eof_meta_bytes = borsh::to_vec(&eof_metadata)?;
                    self.hasher.update(eof_meta_bytes.as_slice());
                    eof_metadata.disk_hash_sha256 = self.hasher.finalize_reset().into();
                    eof_meta_bytes = borsh::to_vec(&eof_metadata)?;
                    buf.put(eof_meta_bytes.as_slice());

                    if let Some(notifier) = &self.notifier {
                        notifier.send_next(
                            self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                            Message::Finished,
                        )?;
                    }
                    self.finished = true;
                }
            }
            Err(err) => {
                return Err(anyhow!(
                    "[FooterGenerator] Error processing messages: {}",
                    err
                ))
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}
