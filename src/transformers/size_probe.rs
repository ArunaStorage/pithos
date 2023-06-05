use crate::notifications::Message;
use crate::transformer::Transformer;
use anyhow::Result;

pub struct SizeProbe {
    size_counter: u64,
    id: u64,
}

impl SizeProbe {
    #[allow(dead_code)]
    pub fn new() -> SizeProbe {
        SizeProbe {
            size_counter: 0,
            id: 0,
        }
    }
}

#[async_trait::async_trait]
impl Transformer for SizeProbe {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        self.size_counter += buf.len() as u64;
        Ok(true)
    }
    async fn notify(&mut self, message: Message) -> Result<Message> {
        Ok(Message {
            recipient: 0,
            info: Some(self.size_counter.into()),
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
