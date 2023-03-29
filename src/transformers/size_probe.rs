use crate::transformer::AddTransformer;
use crate::transformer::Data;
use crate::transformer::Notifications;
use crate::transformer::Transformer;
use anyhow::anyhow;
use anyhow::Result;

pub struct SizeProbe<'a> {
    size_counter: u64,
    id: usize,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> SizeProbe<'a> {
    #[allow(dead_code)]
    pub fn new(id: usize) -> SizeProbe<'a> {
        SizeProbe {
            size_counter: 0,
            id,
            next: None,
        }
    }
}

impl<'a> AddTransformer<'a> for SizeProbe<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for SizeProbe<'_> {
    async fn process_bytes(&mut self, mut buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        self.size_counter += buf.len() as u64;
        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
            next.process_bytes(&mut buf, finished).await
        } else {
            Err(anyhow!(
                "This transformer is designed to always contain a 'next'"
            ))
        }
    }
    async fn notify(&mut self, notes: &mut Vec<Notifications>) -> Result<()> {
        notes.push(Notifications::Response(Data {
            recipient: format!("SIZE_TAG_{}", self.id),
            info: Some(self.size_counter.to_le_bytes().to_vec()),
        }));
        if let Some(next) = &mut self.next {
            next.notify(notes).await?
        }
        Ok(())
    }
}
