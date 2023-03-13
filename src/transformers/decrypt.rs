use anyhow::anyhow;
use anyhow::Result;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::Key;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce;

use crate::transformer::AddTransformer;
use crate::transformer::Notifications;
use crate::transformer::Transformer;

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub struct ChaCha20Dec<'a> {
    internal_buf: BytesMut,
    encryption_key: Key,
    finished: bool,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> ChaCha20Dec<'a> {
    #[allow(dead_code)]
    pub fn new(dec_key: Vec<u8>) -> Result<ChaCha20Dec<'a>> {
        sodiumoxide::init().map_err(|_| anyhow!("sodiuminit failed"))?;
        Ok(ChaCha20Dec {
            internal_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            encryption_key: Key::from_slice(&dec_key).ok_or(anyhow!("Unable to parse Key"))?,
            next: None,
        })
    }
}

impl<'a> AddTransformer<'a> for ChaCha20Dec<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Dec<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        // Only write if the buffer contains data and the current process is not finished

        if buf.len() != 0 {
            self.internal_buf.put(buf);
        }

        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            let mut bytes = if self.internal_buf.len() / CIPHER_SEGMENT_SIZE > 0 {
                decrypt_chunk(
                    &self.internal_buf.split_to(CIPHER_SEGMENT_SIZE),
                    &self.encryption_key,
                )?
            } else {
                if finished && !self.finished {
                    self.finished = true;
                    if self.internal_buf.len() != 0 {
                        decrypt_chunk(&self.internal_buf.split(), &self.encryption_key)?
                    } else {
                        Bytes::new()
                    }
                } else {
                    Bytes::new()
                }
            };
            // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
            next.process_bytes(&mut bytes, self.finished && self.internal_buf.len() == 0)
                .await
        } else {
            Err(anyhow!(
                "This decrypter is designed to always contain a 'next'"
            ))
        }
    }
    async fn notify(&mut self, notes: &mut Vec<Notifications>) -> Result<()> {
        if let Some(next) = &mut self.next {
            next.notify(notes).await?
        }
        Ok(())
    }
}

pub fn decrypt_chunk(chunk: &[u8], decryption_key: &Key) -> Result<Bytes> {
    let (nonce_slice, data) = chunk.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice).ok_or(anyhow!("unable to read nonce"))?;

    Ok(
        chacha20poly1305_ietf::open(data, None, &nonce, decryption_key)
            .map_err(|_| anyhow!("unable to decrypt part"))?
            .into(),
    )
}
