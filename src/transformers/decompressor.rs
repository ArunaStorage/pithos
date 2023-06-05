use crate::notifications::Message;
use crate::transformer::Transformer;
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
    id: u64,
}

impl ZstdDec {
    #[allow(dead_code)]
    pub fn new() -> ZstdDec {
        ZstdDec {
            internal_buf: ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK)),
            prev_buf: BytesMut::with_capacity(RAW_FRAME_SIZE + CHUNK),
            finished: false,
            id: 0,
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
        // Only write if the buffer contains data and the current process is not finished
        if !buf.is_empty() && !self.finished {
            self.internal_buf.write_buf(buf.split()).await?;
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
