use crate::notifications::{Message, ProbeBroadcast};
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
            sender: None,
        }
    }
}

#[async_trait::async_trait]
impl Transformer for SizeProbe {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        self.size_counter += buf.len() as u64;

        if finished {
            if let Some(s) = &self.sender {
                s.send(Message::ProbeBroadcast(ProbeBroadcast {
                    message: format!("Processed size of: {}", self.size_counter),
                }))
                .await?;
            }
        }

        Ok(true)
    }
    fn add_sender(&mut self, s: Sender<Message>) {
        self.sender = Some(s);
    }
}
