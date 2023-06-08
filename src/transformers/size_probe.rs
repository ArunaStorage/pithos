use crate::notifications::Message;
use crate::transformer::Transformer;
use anyhow::Result;
use async_channel::Sender;


pub struct SizeProbe {
    size_counter: u64,
    sender: Option<Sender<Message>>,
}

impl SizeProbe {
    #[allow(dead_code)]
    pub fn new() -> SizeProbe {
        SizeProbe {
            size_counter: 0,
            sender: None
        }
    }
}

#[async_trait::async_trait]
impl Transformer for SizeProbe {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        self.size_counter += buf.len() as u64;

        if finished {
            if let Some(s) = self.sender {
                s.send(Message::ProbeBroadcast(format!("Processed size of: {}", self.size_counter)))
            }
        }

        Ok(true)
    }
    async fn add_sender(&mut self, s: Sender<Message>) -> Result<()>{
        self.sender = Some(s);
        Ok(())
    }
}
