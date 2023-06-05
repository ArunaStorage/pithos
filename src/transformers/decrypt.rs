use crate::notifications::Message;
use crate::transformer::Transformer;
use anyhow::anyhow;
use anyhow::Result;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::Key;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce;

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub struct ChaCha20Dec<'a> {
    input_buffer: BytesMut,
    output_buffer: BytesMut,
    encryption_key: Key,
    finished: bool,
    backoff_counter: usize,
    id: u64,
}

impl<'a> ChaCha20Dec<'a> {
    #[allow(dead_code)]
    pub fn new(dec_key: Vec<u8>) -> Result<ChaCha20Dec<'a>> {
        sodiumoxide::init().map_err(|_| anyhow!("[AF_DECRYPT] sodiuminit failed"))?;
        Ok(ChaCha20Dec {
            input_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            output_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            backoff_counter: 0,
            encryption_key: Key::from_slice(&dec_key)
                .ok_or_else(|| anyhow!("[AF_DECRYPT] Unable to parse Key"))?,
            id: 0,
        })
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Dec<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        // Only write if the buffer contains data and the current process is not finished

        if !buf.is_empty() {
            self.input_buffer.put(buf.split());
        }

        if self.input_buffer.len() / CIPHER_SEGMENT_SIZE > 0 {
            while self.input_buffer.len() / CIPHER_SEGMENT_SIZE > 0 {
                self.output_buffer.put(decrypt_chunk(
                    &self.input_buffer.split_to(CIPHER_SEGMENT_SIZE),
                    &self.encryption_key,
                )?)
            }
        } else if finished && !self.finished {
            if !self.input_buffer.is_empty() {
                if self.input_buffer.len() > 28 {
                    self.finished = true;
                    if !self.input_buffer.is_empty() {
                        self.output_buffer.put(decrypt_chunk(
                            &self.input_buffer.split(),
                            &self.encryption_key,
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

    async fn notify(&mut self, message: Message) -> Result<Message> {
        Ok(Message::default())
    }

    fn set_id(&mut self, id: u64) {
        self.id = id
    }

    fn get_id(&self) -> u64 {
        self.id
    }
}

pub fn decrypt_chunk(chunk: &[u8], decryption_key: &Key) -> Result<Bytes> {
    let (nonce_slice, data) = chunk.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice)
        .ok_or_else(|| anyhow!("[AF_DECRYPT] unable to read nonce"))?;

    let (data, padding) = if chunk.ends_with(&[0u8]) {
        let padding = chunk
            .iter()
            .rev()
            .fold((BytesMut::new(), false), |mut acc, elem| {
                if *elem == 0u8 && !acc.1 {
                    acc.0.put_u8(*elem);
                    (acc.0, false)
                } else {
                    (acc.0, true)
                }
            })
            .0
            .freeze();

        (
            data.split_at(CIPHER_SEGMENT_SIZE - padding.len() - 12).0,
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
