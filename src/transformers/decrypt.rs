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

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub struct ChaCha20Dec {
    input_buffer: BytesMut,
    output_buffer: BytesMut,
    decryption_key: Vec<u8>,
    finished: bool,
    backoff_counter: usize,
}

impl ChaCha20Dec {
    #[allow(dead_code)]
    pub fn new(dec_key: Vec<u8>) -> Result<Self> {
        Ok(ChaCha20Dec {
            input_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            output_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            backoff_counter: 0,
            decryption_key: dec_key,
        })
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Dec {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
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
                    log::debug!(
                        "[AF_DECRYPT] Buffer too small {}, starting backoff_counter: {}",
                        self.input_buffer.len(),
                        self.backoff_counter
                    );

                    self.backoff_counter += 1;

                    if self.backoff_counter > 100 {
                        self.input_buffer.clear();
                        self.finished = true;
                        log::debug!(
                            "[AF_DECRYPT] Buffer too small {}, backoff reached, discarding rest",
                            self.input_buffer.len()
                        );
                    }
                }
            } else {
                self.finished = true;
            }
        };
        buf.put(self.output_buffer.split().freeze());
        Ok(self.finished && self.input_buffer.is_empty() && self.output_buffer.is_empty())
    }

    fn get_type(&self) -> TransformerType {
        TransformerType::ChaCha20Decrypt
    }
}

#[inline]
pub fn decrypt_chunk(chunk: &[u8], decryption_key: &[u8]) -> Result<Bytes> {
    if chunk.len() < 15 {
        bail!("[CHACHA_DECRYPT] Unexpected chunk size < 15")
    }

    let (nonce_slice, data) = chunk.split_at(12);

    if nonce_slice.len() != 12 {
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
        .map_err(|_| anyhow::anyhow!("[CHACHA_DECRYPT] Unable to initialize decryptor"))?
        .decrypt(nonce_slice.into(), payload)
        .map_err(|_| anyhow::anyhow!("[CHACHA_DECRYPT] Unable to decrypt chunk"))?
        .into())
}
