use crate::transformer::AddTransformer;
use crate::transformer::Notifications;
use crate::transformer::Sink;
use crate::transformer::Transformer;
use anyhow::Result;

use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncWrite, BufWriter};

pub struct WriterSink<W: AsyncWrite + Unpin + Send> {
    writer: BufWriter<W>,
}

impl<W: AsyncWrite + Unpin + Send> Sink for WriterSink<W> {}

impl<W: AsyncWrite + Unpin + Send> WriterSink<W> {
    pub fn new(writer: BufWriter<W>) -> Self {
        Self { writer: writer }
    }
}

impl<'a, W: AsyncWrite + Unpin + Send> AddTransformer<'a> for WriterSink<W> {
    fn add_transformer(self: &mut WriterSink<W>, _t: Box<dyn Transformer + Send + 'a>) {}
}

#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send> Transformer for WriterSink<W> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        if buf.len() != 0 {
            self.writer.write_buf(buf).await?;
        } else if finished {
            self.writer.flush().await?;
            self.writer.shutdown().await?;
            return Ok(true);
        }
        Ok(false)
    }
    async fn notify(&mut self, _notes: &mut Vec<Notifications>) -> Result<()> {
        Ok(())
    }
}
