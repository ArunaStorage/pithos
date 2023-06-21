use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use async_compression::tokio::write::GzipEncoder;
use bytes::BufMut;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

const RAW_FRAME_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct ZstdEnc {
    internal_buf: GzipEncoder<Vec<u8>>,
    prev_buf: BytesMut,
    size_counter: usize,
    finished: bool,
}

impl ZstdEnc {
    #[allow(dead_code)]
    pub fn new() -> Self {
        ZstdEnc {
            internal_buf: GzipEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK)),
            prev_buf: BytesMut::with_capacity(RAW_FRAME_SIZE + CHUNK),
            size_counter: 0,
            finished: false,
        }
    }
}

#[async_trait::async_trait]
impl Transformer for ZstdEnc {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        // Create a new frame if buf would increase size_counter to more than RAW_FRAME_SIZE
        if self.size_counter + buf.len() > RAW_FRAME_SIZE {
            // Check how much bytes are missing
            let dif = RAW_FRAME_SIZE - self.size_counter;
            // Make sure that dif is <= RAW_FRAME_SIZE
            assert!(dif <= RAW_FRAME_SIZE);
            self.internal_buf.write_buf(&mut buf.split_to(dif)).await?;
            // Shut the writer down -> Calls flush()
            self.internal_buf.shutdown().await?;
            // Get data from the vector buffer to the "prev_buf" -> Output buffer
            self.prev_buf.extend_from_slice(self.internal_buf.get_ref());
            // Create a new Encoder
            self.internal_buf = GzipEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK));
            // Reset the size_counter
            self.size_counter = 0;

            buf.put(self.prev_buf.split().freeze());
            return Ok(self.finished && self.prev_buf.is_empty());
        }

        // Only write if the buffer contains data and the current process is not finished
        if !buf.is_empty() && !self.finished {
            self.size_counter += buf.len();
            self.internal_buf.write_buf(buf).await?;
        }

        // Add the "last" skippable frame if the previous writer is finished but this one is not!
        if !self.finished && finished && buf.is_empty() {
            self.internal_buf.shutdown().await?;
            self.prev_buf.extend_from_slice(self.internal_buf.get_ref());
            buf.put(self.prev_buf.split().freeze());
            self.finished = true;
            return Ok(self.finished && self.prev_buf.is_empty());
        }
        buf.put(self.prev_buf.split().freeze());
        Ok(self.finished && self.prev_buf.is_empty())
    }

    fn get_type(&self) -> TransformerType {
        TransformerType::GzipCompressor
    }
}
