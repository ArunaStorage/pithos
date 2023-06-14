use crate::transformer::Transformer;
use anyhow::anyhow;
use anyhow::Result;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::AeadCore;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;

pub struct ChaCha20Enc {
    input_buf: BytesMut,
    output_buf: BytesMut,
    add_padding: bool,
    encryption_key: Vec<u8>,
    finished: bool,
}

impl ChaCha20Enc {
    #[allow(dead_code)]
    pub fn new(add_padding: bool, enc_key: Vec<u8>) -> Result<Self> {
        Ok(ChaCha20Enc {
            input_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            output_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            add_padding,
            finished: false,
            encryption_key: enc_key,
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
                    Payload {
                        msg: &self.input_buf.split(),
                        aad: b"",
                    },
                    &self.encryption_key,
                )?)
            }
        } else if finished && !self.finished {
            if self.input_buf.is_empty() {
                self.finished = true;
            } else if self.add_padding {
                self.finished = true;
                let data = self.input_buf.split();
                let pload = generate_padded_payload(
                    ENCRYPTION_BLOCK_SIZE - (self.input_buf.len() % ENCRYPTION_BLOCK_SIZE),
                    &data,
                )?;
                let aad = pload.aad.clone();
                self.output_buf
                    .put(encrypt_chunk(pload, &self.encryption_key)?);
                self.output_buf.put(aad);
            } else {
                self.finished = true;
                self.output_buf.put(encrypt_chunk(
                    Payload {
                        msg: &self.input_buf.split(),
                        aad: b"",
                    },
                    &self.encryption_key,
                )?)
            }
        };
        buf.put(self.output_buf.split());
        Ok(self.finished && self.input_buf.is_empty())
    }
}

pub fn encrypt_chunk(payload: Payload, enc: &[u8]) -> Result<Bytes> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut bytes = BytesMut::new();
    bytes.put(nonce.as_ref());
    let cipher = ChaCha20Poly1305::new_from_slice(enc)
        .map_err(|_| anyhow!("[AF_ENCRYPT] Unable to initialize cipher from key"))?;
    let mut result = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| anyhow!("[AF_ENCRYPT] Unable to encrypt chunk"))?;

    while result.ends_with(&[0u8]) {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        result = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| anyhow!("[AF_ENCRYPT] Unable to encrypt chunk"))?;
    }

    bytes.put(result.as_ref());
    Ok(bytes.freeze())
}

pub fn generate_padded_payload<'a>(size: usize, data: &'a [u8]) -> Result<Payload<'a, 'a>> {
    match size {
        0 => Ok(Payload {
            msg: data,
            aad: b"",
        }),
        1 => Ok(Payload {
            msg: data,
            aad: &[0u8],
        }),
        2 => Ok(Payload {
            msg: data,
            aad: &[0u8, 0u8],
        }),
        3 => Ok(Payload {
            msg: data,
            aad: &[0u8, 0u8, 0u8],
        }),
        size => {
            let mut padding = vec![0u8; size - 4];
            let as_u16 = u16::try_from(size)?;
            padding.extend(as_u16.to_be_bytes());
            padding.push(0u8);
            Ok(Payload {
                msg: data,
                aad: &padding,
            })
        }
    }
}
