use crate::transformer::Sink;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;

use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncWrite, BufWriter};

pub struct WriterSink<W: AsyncWrite + Unpin> {
    writer: BufWriter<W>,
}

impl<W: AsyncWrite + Unpin + Send> Sink for WriterSink<W> {}

impl<W: AsyncWrite + Unpin> WriterSink<W> {
    #[tracing::instrument(level = "trace", skip(writer))]
    pub fn new(writer: BufWriter<W>) -> Self {
        Self { writer }
    }
}

#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send> Transformer for WriterSink<W> {
    #[tracing::instrument(level = "trace", skip(self, buf, finished))]
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        _: bool,
    ) -> Result<bool> {
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

    #[tracing::instrument(level = "trace", skip(self))]
    fn get_type(&self) -> TransformerType {
        TransformerType::WriterSink
    }
}
