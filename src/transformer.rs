use anyhow::Result;
use bytes::Bytes;

#[async_trait::async_trait]
pub trait Transformer {
    async fn write(&mut self, buf: &mut bytes::Bytes) -> Result<()>;
    async fn get_chunk(&mut self) -> Result<Option<Bytes>>;
    async fn finish(mut self, is_last: bool) -> Result<Vec<Bytes>>;
}
