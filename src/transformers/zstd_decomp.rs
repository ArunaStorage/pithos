use crate::notifications::Message;
use crate::notifications::Response;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use async_compression::tokio::write::ZstdDecoder;
use bytes::BufMut;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

const RAW_FRAME_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct ZstdDec {
    internal_buf: ZstdDecoder<Vec<u8>>,
    prev_buf: BytesMut,
    finished: bool,
    skip_me: bool,
    should_flush: bool,
}

impl ZstdDec {
    #[allow(dead_code)]
    pub fn new() -> ZstdDec {
        ZstdDec {
            internal_buf: ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK)),
            prev_buf: BytesMut::with_capacity(RAW_FRAME_SIZE + CHUNK),
            finished: false,
            skip_me: false,
            should_flush: false,
        }
    }
}

impl Default for ZstdDec {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transformer for ZstdDec {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        if self.skip_me {
            return Ok(finished);
        }
        if self.should_flush {
            self.internal_buf.write_buf(buf).await?;
            self.internal_buf.shutdown().await?;
            self.prev_buf.put(self.internal_buf.get_ref().as_slice());
            self.internal_buf = ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK));
            self.should_flush = false;
            buf.put(self.prev_buf.split().freeze());
            return Ok(finished);
        }

        // Only write if the buffer contains data and the current process is not finished
        if !buf.is_empty() && !self.finished {
            self.internal_buf.write_buf(buf).await?;
            while !buf.is_empty() {
                self.internal_buf.shutdown().await?;
                self.prev_buf.put(self.internal_buf.get_ref().as_slice());
                self.internal_buf = ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK));
                self.internal_buf.write_buf(buf).await?;
            }
        }

        if !self.finished && buf.is_empty() && finished {
            self.internal_buf.shutdown().await?;
            self.prev_buf.put(self.internal_buf.get_ref().as_slice());
            self.finished = true;
        }

        buf.put(self.prev_buf.split().freeze());
        Ok(self.finished && self.prev_buf.is_empty())
    }

    #[inline]
    fn get_type(&self) -> TransformerType {
        TransformerType::ZstdDecompressor
    }
    async fn notify(&mut self, message: &Message) -> Result<Response> {
        if message.target == TransformerType::All {
            if let crate::notifications::MessageData::NextFile(nfile) = &message.data {
                self.should_flush = true;
                self.skip_me = nfile.context.skip_decompression
            }
        }
        Ok(Response::Ok)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_zstd_decoder_with_skip() {
        let mut decoder = ZstdDec::new();
        let mut buf = BytesMut::new();
        let expected = hex::decode(format!(
            "28b52ffd00582900003132333435502a4d18eaff{}",
            "00".repeat(65516)
        ))
        .unwrap();
        buf.put(expected.as_slice());
        decoder.process_bytes(&mut buf, true).await.unwrap();
        // Expect 65kb size
        assert_eq!(buf.len(), 5);
        assert_eq!(buf, b"12345".as_slice());
    }

    #[tokio::test]
    async fn test_zstd_encoder_without_skip() {
        let mut decoder = ZstdDec::new();
        let mut buf = BytesMut::new();
        let expected = hex::decode(format!("28b52ffd00582900003132333435",)).unwrap();
        buf.put(expected.as_slice());
        decoder.process_bytes(&mut buf, true).await.unwrap();
        // Expect 65kb size
        assert_eq!(buf.len(), 5);
        assert_eq!(buf, b"12345".as_slice());
    }
}
