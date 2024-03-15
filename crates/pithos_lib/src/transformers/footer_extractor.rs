use crate::helpers::footer_parser::{Footer, FooterParser};
use crate::helpers::notifications::{Message, Notifier};
use crate::pithos::structs::ZSTD_MAGIC_BYTES_SKIPPABLE_2;
use crate::transformer::{Transformer, TransformerType};
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::{BufMut, BytesMut};
use std::sync::Arc;
use tracing::error;

pub struct FooterExtractor {
    footer_sender: Sender<Footer>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    buffer: BytesMut,
    key: Option<[u8; 32]>,
    sequence_start: u8,
    detected: bool,
}

impl FooterExtractor {
    #[tracing::instrument(level = "trace", skip())]
    #[allow(dead_code)]
    pub fn new(recipient_key: Option<[u8; 32]>) -> (FooterExtractor, Receiver<Footer>) {
        let (footer_sender, footer_receiver) = async_channel::bounded(1);
        (
            FooterExtractor {
                notifier: None,
                idx: None,
                msg_receiver: None,
                footer_sender,
                buffer: BytesMut::new(),
                key: recipient_key,
                sequence_start: 0,
                detected: false,
            },
            footer_receiver,
        )
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => {
                        return Ok(true);
                    }
                    Ok(_) => {}
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Closed) => {
                        error!("Message receiver closed");
                        return Err(anyhow!("Message receiver closed"));
                    }
                }
            }
        }
        Ok(false)
    }
}

#[async_trait::async_trait]
impl Transformer for FooterExtractor {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::FooterExtractor, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        let Ok(finished) = self.process_messages() else {
            return Err(anyhow!("HashingTransformer: Error processing messages"));
        };

        if self.detected {
            self.buffer.put(buf);
        } else {
            for (idx, byte) in buf.iter().enumerate() {
                if self.sequence_start == ZSTD_MAGIC_BYTES_SKIPPABLE_2.len() as u8 {
                    self.sequence_start = 0;
                    self.buffer.put(ZSTD_MAGIC_BYTES_SKIPPABLE_2.as_slice());
                    self.buffer.put(&buf[idx..]);
                    break;
                } else if byte == &ZSTD_MAGIC_BYTES_SKIPPABLE_2[self.sequence_start as usize] {
                    self.sequence_start += 1;
                }
            }
        }

        if finished {
            let mut parser = FooterParser::new(self.buffer.as_ref())?;
            if let Some(key) = self.key.as_ref() {
                parser = parser.add_recipient(key);
            }
            parser = parser.parse()?;
            self.footer_sender.try_send(parser.try_into()?)?;
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}
