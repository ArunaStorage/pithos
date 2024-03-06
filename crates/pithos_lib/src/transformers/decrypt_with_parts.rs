use crate::helpers::notifications::{Message, Notifier};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use anyhow::{anyhow, bail};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use std::collections::VecDeque;
use std::sync::Arc;
use tracing::debug;
use tracing::error;

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub struct ChaCha20DecParts {
    input_buffer: BytesMut,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    decryption_key: [u8; 32],
    chunk_lengths: VecDeque<u64>, // File data+meta keys
    skip_me: bool,
}

impl ChaCha20DecParts {
    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new_with_lengths(key: [u8; 32], lengths: Vec<u64>) -> Self {
        ChaCha20DecParts {
            input_buffer: BytesMut::with_capacity(5 * CIPHER_SEGMENT_SIZE),
            decryption_key: key,
            skip_me: false,
            notifier: None,
            msg_receiver: None,
            chunk_lengths: VecDeque::from(lengths),
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::ShouldFlush) | Ok(Message::Finished) => return Ok(true),
                    Ok(Message::Skip) => {
                        self.skip_me = true;
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
impl Transformer for ChaCha20DecParts {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::ChaCha20Decrypt, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        if self.skip_me {
            debug!("skipped");
            return Ok(());
        }

        let Ok(finished) = self.process_messages() else {
            return Err(anyhow!("Error processing messages"));
        };

        if !buf.is_empty() {
            self.input_buffer.put(buf.split());
        }

        loop {
            if let Some(len) = self.chunk_lengths.front_mut() {
                if *len as usize >= CIPHER_SEGMENT_SIZE
                    && self.input_buffer.len() >= CIPHER_SEGMENT_SIZE
                {
                    buf.put(decrypt_chunk(
                        &self.input_buffer.split_to(CIPHER_SEGMENT_SIZE),
                        &self.decryption_key,
                    )?);
                    *len -= CIPHER_SEGMENT_SIZE as u64;
                    if *len == 0 {
                        self.chunk_lengths.pop_front();
                        break;
                    }
                } else if (*len as usize) < CIPHER_SEGMENT_SIZE
                    && self.input_buffer.len() >= *len as usize
                {
                    buf.put(decrypt_chunk(
                        &self.input_buffer.split_to(*len as usize),
                        &self.decryption_key,
                    )?);
                    self.chunk_lengths.pop_front();
                } else {
                    break;
                }
            } else {
                self.input_buffer.clear();
                break;
            }
        }

        if finished && self.input_buffer.is_empty() {
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
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

#[tracing::instrument(level = "trace", skip(chunk, decryption_key))]
#[inline]
pub fn decrypt_chunk(chunk: &[u8], decryption_key: &[u8; 32]) -> Result<Bytes> {
    if chunk.len() < 15 {
        error!(len = chunk.len(), "Unexpected chunk size < 15");
        bail!("[CHACHA_DECRYPT] Unexpected chunk size < 15")
    }

    let (nonce_slice, data) = chunk.split_at(12);

    if nonce_slice.len() != 12 {
        error!(len = nonce_slice.len(), "Invalid nonce size");
        bail!("[CHACHA_DECRYPT] Invalid nonce")
    }

    let payload = Payload {
        msg: data,
        aad: b"",
    };
    Ok(ChaCha20Poly1305::new_from_slice(decryption_key)
        .map_err(|e| {
            error!(?e, "Unable to initialize decryptor");
            anyhow::anyhow!("[CHACHA_DECRYPT] Unable to initialize decryptor")
        })?
        .decrypt(nonce_slice.into(), payload)
        .map_err(|_| anyhow::anyhow!("[CHACHA_DECRYPT] Unable to decrypt chunk"))?
        .into())
}
