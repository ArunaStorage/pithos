use std::collections::HashMap;

use anyhow::Result;

pub struct Stats {
    _origin: String,
    _items: HashMap<String, String>,
}

#[async_trait::async_trait]
pub trait Transformer {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool>;
    async fn get_info(&mut self, is_last: bool) -> Result<Vec<Stats>>;
}
