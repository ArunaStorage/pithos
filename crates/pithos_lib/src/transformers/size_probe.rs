use crate::notifications::{Message, ProbeBroadcast};
use crate::transformer::{Transformer, TransformerType};
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender};
use tracing::error;

pub struct SizeProbe {
    size_counter: u64,
    sender: Option<Sender<Message>>,
    size_sender: Sender<u64>,
}

impl SizeProbe {
    #[tracing::instrument(level = "trace", skip())]
    #[allow(dead_code)]
    pub fn new() -> (SizeProbe, Receiver<u64>) {
        let (size_sender, size_receiver) = async_channel::bounded(1);

        (
            SizeProbe {
                size_counter: 0,
                sender: None,
                size_sender,
            },
            size_receiver,
        )
    }
}

#[async_trait::async_trait]
impl Transformer for SizeProbe {
    #[tracing::instrument(level = "trace", skip(self, buf, finished))]
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        _: bool,
    ) -> Result<bool> {
        self.size_counter += buf.len() as u64;

        if finished && buf.is_empty() {
            if let Some(s) = &self.sender {
                s.send(Message {
                    target: TransformerType::ReadWriter,
                    data: crate::notifications::MessageData::ProbeBroadcast(ProbeBroadcast {
                        message: format!("Processed size of: {}", self.size_counter),
                    }),
                })
                .await?;
                match self.size_sender.try_send(self.size_counter) {
                    Ok(_) => {}
                    Err(e) => match e {
                        async_channel::TrySendError::Full(_) => {}
                        async_channel::TrySendError::Closed(_) => {
                            error!("Sending in closed channel");
                            return Err(anyhow!("SizeProbe: Channel closed"))
                        }
                    },
                };
            }
        }

        Ok(true)
    }
    #[tracing::instrument(level = "trace", skip(self, s))]
    fn add_sender(&mut self, s: Sender<Message>) {
        self.sender = Some(s);
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn get_type(&self) -> TransformerType {
        TransformerType::SizeProbe
    }
}
