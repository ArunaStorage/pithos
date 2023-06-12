use crate::transformer::Transformer;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::Nonce;

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
        Ok(self.finished && self.input_buffer.is_empty())
    }
}

pub fn decrypt_chunk(chunk: &[u8], decryption_key: &[u8]) -> Result<Bytes> {
    // TODO: Split off MAC !
    let (nonce_slice, data) = chunk.split_at(12);

    let (data, padding) = if chunk.ends_with(&[0u8]) {
        let mut padding = BytesMut::with_capacity(65_536);
        let mut padsize = 0u64;
        let mut expected_end = BytesMut::with_capacity(12);

        for c in chunk.iter().rev() {
            if *c == 0u8 {
                padding.put_u8(0u8);
                padsize += 1;
            } else {
                if expected_end.is_empty() {
                    break;
                } else {
                    expected_end.put(padsize.to_le_bytes().as_ref());
                    expected_end.reverse();
                    if expected_end.get_u8() == *c {
                        padsize += 1;
                        padding.put_u8(*c);
                    } else {
                        bail!("[CHACHA_DECRYPT] Error unexpected padding")
                    }
                }
            }
        }

        (
            data.split_at(CIPHER_SEGMENT_SIZE - padsize as usize - 12).0,
            Some(padding),
        )
    } else {
        (data, None)
    };

    Ok(chacha20poly1305_ietf::open(
        data,
        padding.as_ref().map(|e| e.as_ref()),
        &nonce,
        decryption_key,
    )
    .map_err(|_| anyhow!("[AF_DECRYPT] unable to decrypt part"))?
    .into())
}
