use crate::notifications::{Message, Notifier};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use anyhow::{anyhow, bail};
use async_channel::{Receiver, Sender, TryRecvError};
use byteorder::BigEndian;
use byteorder::ByteOrder;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use std::sync::Arc;
use tracing::debug;
use tracing::error;
use tracing::info;

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub struct ChaCha20Dec {
    input_buffer: BytesMut,
    output_buffer: BytesMut,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    decryption_key: Option<Vec<u8>>,
    key_is_fixed: bool,
    finished: bool,
    backoff_counter: usize,
    skip_me: bool,
}

impl ChaCha20Dec {
    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        Ok(ChaCha20Dec {
            input_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            output_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            backoff_counter: 0,
            decryption_key: None,
            key_is_fixed: false,
            skip_me: false,
            notifier: None,
            msg_receiver: None,
            idx: None,
        })
    }

    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new_with_fixed(key: Vec<u8>) -> Result<Self> {
        Ok(ChaCha20Dec {
            input_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            output_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            backoff_counter: 0,
            decryption_key: Some(key),
            key_is_fixed: true,
            skip_me: false,
            notifier: None,
            msg_receiver: None,
            idx: None,
        })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<(bool, bool)> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::FileContext(ctx)) => {
                        if !self.key_is_fixed && !ctx.is_dir && !ctx.is_symlink {
                            self.decryption_key = ctx.encryption_key;
                        }
                    }
                    Ok(Message::ShouldFlush) => return Ok((true, false)),
                    Ok(Message::Skip) => {
                        self.skip_me = true;
                    }
                    Ok(Message::Finished) => return Ok((false, true)),
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
        Ok((false, false))
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Dec {
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

        let Ok((should_flush, finished)) = self.process_messages() else {
            return Err(anyhow!("Error processing messages"));
        };

        if should_flush {
            self.input_buffer.put(buf.split());

            if !self.input_buffer.is_empty() {
                self.output_buffer.put(decrypt_chunk(
                    &self.input_buffer.split(),
                    self.decryption_key
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing decryption key"))?,
                )?);
            }

            buf.put(self.output_buffer.split().freeze());
            debug!(buf_len = buf.len(), "bytes flushed");
            return Ok(());
        }
        // Only write if the buffer contains data and the current process is not finished

        if !buf.is_empty() {
            self.input_buffer.put(buf.split());
        }

        if self.input_buffer.len() / CIPHER_SEGMENT_SIZE > 0 {
            while self.input_buffer.len() / CIPHER_SEGMENT_SIZE > 0 {
                self.output_buffer.put(decrypt_chunk(
                    &self.input_buffer.split_to(CIPHER_SEGMENT_SIZE),
                    self.decryption_key
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing decryption key"))?,
                )?)
            }
        } else if finished && !self.finished {
            if !self.input_buffer.is_empty() {
                if self.input_buffer.len() > 28 {
                    self.finished = true;
                    if !self.input_buffer.is_empty() {
                        self.output_buffer.put(decrypt_chunk(
                            &self.input_buffer.split(),
                            self.decryption_key
                                .as_ref()
                                .ok_or_else(|| anyhow!("Missing decryption key"))?,
                        )?);
                    }
                } else {
                    info!(
                        len = self.input_buffer.len(),
                        self.backoff_counter, "Buffer too small, backoff"
                    );

                    self.backoff_counter += 1;

                    if self.backoff_counter > 10 {
                        self.input_buffer.clear();
                        self.finished = true;
                        error!(
                            len = self.input_buffer.len(),
                            "Buffer too small, backoff reached, discarding rest"
                        );
                        bail!("Buffer too small, backoff reached, would discard rest");
                    }
                }
            } else {
                self.finished = true;
            }
        };
        buf.put(self.output_buffer.split().freeze());

        if self.finished && self.input_buffer.is_empty() && self.output_buffer.is_empty() {
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
pub fn decrypt_chunk(chunk: &[u8], decryption_key: &[u8]) -> Result<Bytes> {
    if chunk.len() < 15 {
        error!(len = chunk.len(), "Unexpected chunk size < 15");
        bail!("[CHACHA_DECRYPT] Unexpected chunk size < 15")
    }

    let (nonce_slice, data) = chunk.split_at(12);

    if nonce_slice.len() != 12 {
        error!(len = nonce_slice.len(), "Invalid nonce size");
        bail!("[CHACHA_DECRYPT] Invalid nonce")
    }

    let last_4 = {
        let (l1, rem) = data.split_last().unwrap_or((&0u8, &[0u8]));
        let (l2, rem) = rem.split_last().unwrap_or((&0u8, &[0u8]));
        let (l3, rem) = rem.split_last().unwrap_or((&0u8, &[0u8]));
        let (l4, _) = rem.split_last().unwrap_or((&0u8, &[0u8]));
        (l4, l3, l2, l1)
    };

    // Padding definition
    // Encryption with padding must ensure that MAC does not end with 0x00
    // Padding is signaled by a 0x00 byte in the end, followed by the number of padding 0x00 bytes
    // <data_ends_with_MAC: ...0abc01230a><padding: 0x0000000000000><padsize (u16): 0x0000><sentinel: 0x00>
    // Special cases: 1, 2, 3 0x00
    let mut padding;

    let payload = match last_4 {
        (0u8, size1, size2, 0u8) => {
            let expected = [*size1, *size2];
            let v = BigEndian::read_u16(&expected);
            padding = vec![0u8; v as usize - 4];
            padding.extend_from_slice(&[0u8, *size1, *size2, 0u8]);
            Payload {
                msg: &data[..data.len() - v as usize],
                aad: &padding,
            }
        }
        (_, 0u8, 0u8, 0u8) => Payload {
            msg: &data[..data.len() - 3],
            aad: &[0u8, 0u8, 0u8],
        },
        (_, _, 0u8, 0u8) => Payload {
            msg: &data[..data.len() - 2],
            aad: &[0u8, 0u8],
        },
        (_, _, _, 0u8) => Payload {
            msg: &data[..data.len() - 1],
            aad: &[0u8],
        },
        _ => Payload {
            msg: data,
            aad: b"",
        },
    };

    Ok(ChaCha20Poly1305::new_from_slice(decryption_key)
        .map_err(|e| {
            error!(?e, "Unable to initialize decryptor");
            anyhow::anyhow!("[CHACHA_DECRYPT] Unable to initialize decryptor")
        })?
        .decrypt(nonce_slice.into(), payload)
        .map_err(|e| {
            error!(?e, "Unable to initialize decryptor");
            anyhow::anyhow!("[CHACHA_DECRYPT] Unable to decrypt chunk")
        })?
        .into())
}
