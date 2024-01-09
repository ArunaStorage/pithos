use crate::notifications::Message;
use crate::notifications::Response;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::bail;
use anyhow::Result;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use tracing::debug;
use tracing::error;
use tracing::info;

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub struct ChaCha20Dec {
    input_buffer: BytesMut,
    output_buffer: BytesMut,
    hard_coded_enc: bool,
    decryption_key: Vec<u8>,
    finished: bool,
    backoff_counter: usize,
    skip_me: bool,
}

impl ChaCha20Dec {
    #[tracing::instrument(level = "trace", skip(dec_key))]
    #[allow(dead_code)]
    pub fn new(dec_key: Option<Vec<u8>>) -> Result<Self> {
        Ok(ChaCha20Dec {
            input_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            output_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            hard_coded_enc: dec_key.is_some(),
            backoff_counter: 0,
            decryption_key: dec_key.unwrap_or_default(),
            skip_me: false,
        })
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Dec {
    #[tracing::instrument(level = "trace", skip(self, buf, finished, should_flush))]
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        should_flush: bool,
    ) -> Result<bool> {
        if self.skip_me {
            debug!("skipped");
            return Ok(finished);
        }

        if should_flush {
            self.input_buffer.put(buf.split());

            if self.input_buffer.len() > 0 {
                self.output_buffer.put(decrypt_chunk(
                    &self.input_buffer.split(),
                    &self.decryption_key,
                )?);
            }
            
            buf.put(self.output_buffer.split().freeze());
            debug!(buf_len = buf.len(), "bytes flushed");
            return Ok(finished);
        }
        // Only write if the buffer contains data and the current process is not finished

        if !buf.is_empty() {
            self.input_buffer.put(buf.split());
        }

        if self.input_buffer.len() / CIPHER_SEGMENT_SIZE > 0 {
            while self.input_buffer.len() / CIPHER_SEGMENT_SIZE > 0 {
                self.output_buffer.put(decrypt_chunk(
                    &self.input_buffer.split_to(CIPHER_SEGMENT_SIZE),
                    &self.decryption_key,
                )?)
            }
        } else if finished && !self.finished {
            if !self.input_buffer.is_empty() {
                if self.input_buffer.len() > 28 {
                    self.finished = true;
                    if !self.input_buffer.is_empty() {
                        self.output_buffer.put(decrypt_chunk(
                            &self.input_buffer.split(),
                            &self.decryption_key,
                        )?);
                    }
                } else {
                    info!(
                        len = self.input_buffer.len(),
                        self.backoff_counter,
                        "Buffer too small, backoff"
                    );

                    self.backoff_counter += 1;

                    if self.backoff_counter > 10 {
                        self.input_buffer.clear();
                        self.finished = true;
                        error!(len = self.input_buffer.len(),
                        "Buffer too small, backoff reached, discarding rest");
                        bail!("Buffer too small, backoff reached, would discard rest");
                    }
                }
            } else {
                self.finished = true;
            }
        };
        buf.put(self.output_buffer.split().freeze());
        Ok(self.finished && self.input_buffer.is_empty() && self.output_buffer.is_empty())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn get_type(&self) -> TransformerType {
        TransformerType::ChaCha20Decrypt
    }

    #[tracing::instrument(level = "trace", skip(self, message))]
    async fn notify(&mut self, message: &Message) -> Result<Response> {
        if message.target == TransformerType::All {
            if let crate::notifications::MessageData::NextFile(nfile) = &message.data {
                self.skip_me = nfile.context.skip_decryption;
                if !self.hard_coded_enc {
                    self.decryption_key = nfile.context.encryption_key.clone().unwrap_or_default();
                }
            }
        }

        Ok(Response::Ok)
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
        .map_err(|e| 
            {
                error!(?e, "Unable to initialize decryptor");
                anyhow::anyhow!("[CHACHA_DECRYPT] Unable to decrypt chunk")
            })?
        .into())
}
