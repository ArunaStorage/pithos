use crate::notifications::Message;
use crate::transformer::Transformer;
use anyhow::anyhow;
use anyhow::Result;

pub struct SizeProbe<'a> {
    size_counter: u64,
    id: usize,
}

impl<'a> SizeProbe<'a> {
    #[allow(dead_code)]
    pub fn new() -> SizeProbe<'a> {
        SizeProbe {
            size_counter: 0,
            id: 0,
        }
    }
}

#[async_trait::async_trait]
impl Transformer for SizeProbe<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        self.size_counter += buf.len() as u64;
        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
            next.process_bytes(buf, finished).await
        } else {
            Err(anyhow!(
                "This transformer is designed to always contain a 'next'"
            ))
        }
    }
    async fn notify(&mut self, message: Message) -> Result<Message> {
        Ok(Message {
            recipient: 0,
            info: Some(self.size_counter),
            message_type: crate::notifications::MessageType::Response,
        })
    }
    fn set_id(&mut self, id: u64) {
        self.id = id
    }
    fn get_id(&self) -> u64 {
        self.id
    }
}
