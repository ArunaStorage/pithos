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

pub struct ChaCha20Enc<'a> {
    internal_buf: BytesMut,
    add_padding: bool,
    encryption_key: Key,
    finished: bool,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> ChaCha20Enc<'a> {
    #[allow(dead_code)]
    pub fn new(add_padding: bool, enc_key: Vec<u8>) -> Result<ChaCha20Enc<'a>> {
        sodiumoxide::init().map_err(|_| anyhow!("sodiuminit failed"))?;
        Ok(ChaCha20Enc {
            internal_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            add_padding,
            finished: false,
            encryption_key: Key::from_slice(&enc_key).ok_or(anyhow!("Unable to parse Key"))?,
            next: None,
        })
    }
}

impl<'a> AddTransformer<'a> for ChaCha20Enc<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Enc<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        // Only write if the buffer contains data and the current process is not finished

        if buf.len() != 0 {
            self.internal_buf.put(buf);
        }

        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            let mut bytes = if self.internal_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
                encrypt_chunk(
                    &self.internal_buf.split_to(ENCRYPTION_BLOCK_SIZE),
                    None,
                    &self.encryption_key,
                )?
            } else {
                if finished && !self.finished {
                    if self.internal_buf.len() == 0 {
                        self.finished = true;
                        Bytes::new()
                    } else {
                        if self.add_padding {
                            self.finished = true;
                            let padding = vec![
                                0u8;
                                ENCRYPTION_BLOCK_SIZE
                                    - (self.internal_buf.len()
                                        % ENCRYPTION_BLOCK_SIZE)
                            ];
                            let mut bytesmut = BytesMut::with_capacity(ENCRYPTION_BLOCK_SIZE);

                            bytesmut.put(encrypt_chunk(
                                &self.internal_buf.split(),
                                Some(&padding),
                                &self.encryption_key,
                            )?);
                            bytesmut.put(padding.as_ref());
                            bytesmut.freeze()
                        } else {
                            self.finished = true;
                            encrypt_chunk(&self.internal_buf.split(), None, &self.encryption_key)?
                        }
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
                "This compressor is designed to always contain a 'next'"
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

pub fn encrypt_chunk(chunk: &[u8], padding: Option<&[u8]>, enc: &Key) -> Result<Bytes> {
    let nonce = Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
        .ok_or(anyhow!("Unable to create nonce"))?;
    let mut bytes = BytesMut::new();
    bytes.put(nonce.0.as_ref());
    bytes.put(chacha20poly1305_ietf::seal(chunk, padding, &nonce, &enc).as_ref());
    Ok(bytes.freeze())
}
