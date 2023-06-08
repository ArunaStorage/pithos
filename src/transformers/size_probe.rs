use crate::notifications::Message;
use crate::transformer::Transformer;
use anyhow::Result;

pub struct SizeProbe {
    size_counter: u64,
}

impl SizeProbe {
    #[allow(dead_code)]
    pub fn new() -> SizeProbe {
        SizeProbe {
            size_counter: 0,
        }
    }
}

#[async_trait::async_trait]
impl Transformer for SizeProbe {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        self.size_counter += buf.len() as u64;
        Ok(true)
    }
    async fn send_message(&mut self, message: Message) -> Result<Message> {
        Ok(Message {
            recipient: 0,
            info: Some(self.size_counter.to_le_bytes().into()),
            message_type: crate::notifications::MessageType::Response,
        })
    }
}
