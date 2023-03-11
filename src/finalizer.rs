use crate::transformer::Stats;
use crate::transformer::Transformer;
use anyhow::Result;

use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncWrite, BufWriter};

pub struct Finalizer<W: AsyncWrite + Unpin + Send> {
    writer: BufWriter<W>,
}

impl<W: AsyncWrite + Unpin + Send> Finalizer<W> {
    pub async fn new(writer: BufWriter<W>) -> Self {
        Self { writer: writer }
    }
}

#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send> Transformer for Finalizer<W> {
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
    async fn get_info(&mut self, _is_last: bool) -> Result<Vec<Stats>> {
        todo!();
    }
}
