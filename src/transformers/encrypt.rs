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

pub struct ChaCha20Enc {
    input_buf: BytesMut,
    output_buf: BytesMut,
    add_padding: bool,
    encryption_key: Key,
    finished: bool,
}

impl ChaCha20Enc {
    #[allow(dead_code)]
    pub fn new(add_padding: bool, enc_key: Vec<u8>) -> Result<Self> {
        sodiumoxide::init().map_err(|_| anyhow!("sodiuminit failed"))?;
        Ok(ChaCha20Enc {
            input_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            output_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            add_padding,
            finished: false,
            encryption_key: Key::from_slice(&enc_key)
                .ok_or_else(|| anyhow!("Unable to parse Key"))?,
        })
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Enc {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        // Only write if the buffer contains data and the current process is not finished

        if !buf.is_empty() {
            self.input_buf.put(buf.split());
        }
        if self.input_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
            while self.input_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split_to(ENCRYPTION_BLOCK_SIZE),
                    None,
                    &self.encryption_key,
                )?)
            }
        } else if finished && !self.finished {
            if self.input_buf.is_empty() {
                self.finished = true;
            } else if self.add_padding {
                self.finished = true;
                let padding = vec![
                    0u8;
                    ENCRYPTION_BLOCK_SIZE
                        - (self.input_buf.len() % ENCRYPTION_BLOCK_SIZE)
                ];

                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split(),
                    Some(&padding),
                    &self.encryption_key,
                )?);
                self.output_buf.put(padding.as_ref());
            } else {
                self.finished = true;
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split(),
                    None,
                    &self.encryption_key,
                )?)
            }
        };
        buf.put(self.output_buf.split());
        Ok(self.finished && self.input_buf.is_empty())
    }
}

pub fn encrypt_chunk(chunk: &[u8], padding: Option<&[u8]>, enc: &Key) -> Result<Bytes> {
    let nonce = Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
        .ok_or_else(|| anyhow!("Unable to create nonce"))?;
    let mut bytes = BytesMut::new();
    bytes.put(nonce.0.as_ref());

    let mut sealed_result = chacha20poly1305_ietf::seal(chunk, padding, &nonce, enc);

    bytes.put(sealed_result.as_ref());

    while sealed_result.last().ok_or_else(|| anyhow!("Wrong data"))? == &0u8 {
        bytes.clear();
        let nonce = Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
            .ok_or_else(|| anyhow!("Unable to create nonce"))?;
        bytes.put(nonce.0.as_ref());
        sealed_result = chacha20poly1305_ietf::seal(chunk, padding, &nonce, enc);
        bytes.put(sealed_result.as_ref());
    }
    Ok(bytes.freeze())
}
