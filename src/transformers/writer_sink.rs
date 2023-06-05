use crate::notifications::Message;
use crate::transformer::Sink;
use crate::transformer::Transformer;
use anyhow::Result;

use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncWrite, BufWriter};

pub struct WriterSink<W: AsyncWrite + Unpin + Send> {
    writer: BufWriter<W>,
    id: u64,
}

impl<W: AsyncWrite + Unpin + Send> Sink for WriterSink<W> {}

impl<W: AsyncWrite + Unpin + Send> WriterSink<W> {
    pub fn new(writer: BufWriter<W>) -> Self {
        Self { writer, id: 0 }
    }
}

#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send> Transformer for WriterSink<W> {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        if !buf.is_empty() {
            while !buf.is_empty() {
                self.writer.write_buf(buf).await?;
            }
        } else if finished {
            self.writer.flush().await?;
            self.writer.shutdown().await?;
            return Ok(true);
        }
        Ok(false)
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
