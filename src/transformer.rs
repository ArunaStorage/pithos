use std::collections::HashMap;

use anyhow::Result;

pub struct Stats {
    _origin: String,
    _items: HashMap<String, String>,
}

pub trait AddTransformer<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>);
}

#[async_trait::async_trait]
pub trait Transformer {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool>;
    async fn get_info(&mut self, is_last: bool) -> Result<Vec<Stats>>;
}
