use crate::helpers::footer_parser::Range;
use crate::notifications::{Message, Notifier};
use crate::transformer::{Transformer, TransformerType};
use anyhow::{anyhow, Result};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::Buf;
use std::sync::Arc;
use tracing::error;

pub struct Filter {
    counter: usize,
    filter: Range,
    captured_buf_len: usize,
    advanced_by: usize,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl Filter {
    #[tracing::instrument(level = "trace", skip(filter))]
    #[allow(dead_code)]
    pub fn new(filter: Range) -> Self {
        Filter {
            counter: 0,
            filter,
            captured_buf_len: 0,
            advanced_by: 0,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => return Ok(true),
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
impl Transformer for Filter {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::Filter, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        self.captured_buf_len = buf.len();
        self.advanced_by = 0;

        // If bytes are present in the buffer
        if !buf.is_empty() {
            // If counter + incoming bytes are larger than lower limit
            //   -> Advance buffer to lower limit
            if ((self.counter + self.captured_buf_len) as u64) > self.filter.from {
                if !(self.counter > self.filter.from as usize) {
                    self.advanced_by = self.filter.from as usize - self.counter;
                    buf.advance(self.advanced_by);
                }
            } else {
                // If counter + incoming bytes are smaller than lower limit
                //   -> discard buffer
                buf.clear();
            }

            if self.counter as u64 > self.filter.to {
                // If counter is larger than upper limit
                //   -> discard buffer
                buf.clear();
            } else if self.counter as u64 + self.captured_buf_len as u64 > self.filter.to {
                // If counter + incoming bytes is larger than upper limit
                //   -> truncate buffer to upper limit
                buf.truncate(self.filter.to as usize - self.advanced_by - self.counter);
            }
        }

        self.counter += self.captured_buf_len;

        if let Ok(finished) = self.process_messages() {
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
            }
        } else {
            return Err(anyhow!("Error processing messages"));
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
