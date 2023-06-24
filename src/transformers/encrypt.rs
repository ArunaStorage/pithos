use crate::notifications::Message;
use crate::notifications::Response;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::bail;
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
    should_flush: bool,
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
            should_flush: false,
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

        if self.should_flush {
            if self.add_padding {
                let data = self.input_buf.split();
                let padding =
                    generate_padding(ENCRYPTION_BLOCK_SIZE - (data.len() % ENCRYPTION_BLOCK_SIZE))?;
                self.output_buf
                    .put(encrypt_chunk(&data, &padding, &self.encryption_key)?);
            } else {
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split(),
                    b"",
                    &self.encryption_key,
                )?)
            }
            buf.put(self.output_buf.split());
            self.should_flush = false;
            return Ok(finished);
        }

        if self.input_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
            while self.input_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split_to(ENCRYPTION_BLOCK_SIZE),
                    b"",
                    &self.encryption_key,
                )?)
            }
        } else if finished && !self.finished {
            if self.input_buf.is_empty() {
                self.finished = true;
            } else if self.add_padding {
                self.finished = true;
                let data = self.input_buf.split();
                let padding =
                    generate_padding(ENCRYPTION_BLOCK_SIZE - (data.len() % ENCRYPTION_BLOCK_SIZE))?;
                self.output_buf
                    .put(encrypt_chunk(&data, &padding, &self.encryption_key)?);
            } else {
                self.finished = true;
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split(),
                    b"",
                    &self.encryption_key,
                )?)
            }
        };
        buf.put(self.output_buf.split());
        Ok(self.finished && self.input_buf.is_empty() && self.output_buf.is_empty())
    }

    fn get_type(&self) -> TransformerType {
        TransformerType::ChaCha20Decrypt
    }
    async fn notify(&mut self, message: &Message) -> Result<Response> {
        if message.target == TransformerType::All {
            if let crate::notifications::MessageData::NextFile(_) = &message.data {
                self.should_flush = true;
            }
        }
        Ok(Response::Ok)
    }
}

#[inline]
pub fn encrypt_chunk(msg: &[u8], aad: &[u8], enc: &[u8]) -> Result<Bytes> {
    if msg.len() > ENCRYPTION_BLOCK_SIZE {
        bail!("[CHACHA_ENCRYPT] Invalid encryption block size")
    }

    let mut nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut bytes = BytesMut::new();
    let pload = Payload { msg, aad };
    let cipher = ChaCha20Poly1305::new_from_slice(enc)
        .map_err(|_| anyhow!("[CHACHA_ENCRYPT] Unable to initialize cipher from key"))?;
    let mut result = cipher
        .encrypt(&nonce, pload)
        .map_err(|_| anyhow!("[CHACHA_ENCRYPT] Unable to encrypt chunk"))?;

    while result.ends_with(&[0u8]) {
        let pload = Payload { msg, aad };
        nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        result = cipher
            .encrypt(&nonce, pload)
            .map_err(|_| anyhow!("[CHACHA_ENCRYPT] Unable to encrypt chunk"))?;
    }

    bytes.put(nonce.as_ref());
    bytes.put(result.as_ref());
    bytes.put(aad);

    Ok(bytes.freeze())
}

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
