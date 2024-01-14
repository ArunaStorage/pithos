use crate::notifications::{Message, Notifier};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::AeadCore;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use std::sync::Arc;
use tracing::debug;
use tracing::error;

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;

pub struct ChaCha20Enc {
    input_buf: BytesMut,
    output_buf: BytesMut,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    encryption_key: Option<Vec<u8>>,
    finished: bool,
}

impl ChaCha20Enc {
    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        Ok(ChaCha20Enc {
            input_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            output_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            notifier: None,
            msg_receiver: None,
            idx: None,
            encryption_key: None,
            finished: false,
        })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<(bool, bool)> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::FileContext(ctx)) => {
                        self.encryption_key = ctx.encryption_key;
                    }
                    Ok(Message::ShouldFlush) => return Ok((true, false)),
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
impl Transformer for ChaCha20Enc {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::ChaCha20Encrypt, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut BytesMut) -> Result<()> {
        // Only write if the buffer contains data and the current process is not finished

        if !buf.is_empty() {
            self.input_buf.put(buf.split());
        }

        let Ok((should_flush, finished)) = self.process_messages() else {
            return Err(anyhow!("Error processing messages"));
        };

        if should_flush {
            self.output_buf.put(encrypt_chunk(
                &self.input_buf.split(),
                b"",
                &self
                    .encryption_key
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing encryption key"))?,
                true,
            )?);
            buf.put(self.output_buf.split());
            debug!(?buf, "flushed");
            return Ok(());
        }

        if self.input_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
            while self.input_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split_to(ENCRYPTION_BLOCK_SIZE),
                    b"",
                    &self
                        .encryption_key
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing encryption key"))?,
                    true,
                )?)
            }
        } else if finished && !self.finished {
            if self.input_buf.is_empty() {
                self.finished = true;
            } else {
                self.finished = true;
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split(),
                    b"",
                    &self
                        .encryption_key
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing encryption key"))?,
                    true,
                )?)
            }
        };
        buf.put(self.output_buf.split());

        if self.finished && self.input_buf.is_empty() && self.output_buf.is_empty() {
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

#[tracing::instrument(level = "trace", skip(msg, aad, enc))]
#[inline]
pub fn encrypt_chunk(msg: &[u8], aad: &[u8], enc: &[u8], use_limit: bool) -> Result<Bytes> {
    if use_limit && msg.len() > ENCRYPTION_BLOCK_SIZE {
        error!(len = msg.len(), "Message too large");
        bail!("[CHACHA_ENCRYPT] Invalid encryption block size")
    }

    let mut nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut bytes = BytesMut::new();
    let pload = Payload { msg, aad };
    let cipher = ChaCha20Poly1305::new_from_slice(enc).map_err(|e| {
        error!(error = ?e, ?msg, ?aad, "Unable to initialize cipher from key");
        anyhow!("[CHACHA_ENCRYPT] Unable to initialize cipher from key")
    })?;
    let mut result = cipher.encrypt(&nonce, pload).map_err(|e| {
        error!(error = ?e, ?msg, ?aad, "Unable to encrypt chunk");
        anyhow!("[CHACHA_ENCRYPT] Unable to encrypt chunk")
    })?;

    while result.ends_with(&[0u8]) {
        let pload = Payload { msg, aad };
        nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        result = cipher.encrypt(&nonce, pload).map_err(|e| {
            error!(error = ?e, ?msg, ?aad, "Unable to encrypt chunk");
            anyhow!("[CHACHA_ENCRYPT] Unable to encrypt chunk")
        })?;
    }

    bytes.put(nonce.as_ref());
    bytes.put(result.as_ref());
    bytes.put(aad);

    Ok(bytes.freeze())
}

#[tracing::instrument(level = "trace", skip(size))]
#[inline]
pub fn generate_padding(size: usize) -> Result<Vec<u8>> {
    match size {
        0 => Ok(Vec::new()),
        1 => Ok(vec![0u8]),
        2 => Ok(vec![0u8, 0u8]),
        3 => Ok(vec![0u8, 0u8, 0u8]),
        size => {
            let mut padding = vec![0u8; size - 3];
            let as_u16 = u16::try_from(size)?;
            padding.extend(as_u16.to_be_bytes());
            padding.push(0u8);
            Ok(padding)
        }
    }
}
