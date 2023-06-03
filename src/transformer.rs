use crate::notifications::Notifications;
use anyhow::Result;

// Marker trait to signal that this Transformer can be a "final" destination for data
pub trait Sink {}

pub trait AddTransformer<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>);
}

#[async_trait::async_trait]
pub trait Transformer {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool>;
    async fn notify(&mut self, notes: &mut Vec<Notifications>) -> Result<()>;
}
