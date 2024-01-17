use crate::helpers::footer_parser::Range;
use crate::notifications::{Message, Notifier};
use crate::transformer::{Transformer, TransformerType};
use anyhow::{anyhow, Result};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::{Buf, BufMut, BytesMut};
use std::sync::Arc;
use tracing::{error, warn};

pub enum FilterParam {
    None,
    Discard(u64),
    Keep(u64),
}

pub struct Filter {
    has_filter: bool,
    param: FilterParam,
    filter: Vec<u64>,
    captured_buf_len: usize,
    advanced_by: usize,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl Filter {
    #[tracing::instrument(level = "trace", skip(filter))]
    #[allow(dead_code)]
    pub fn new_with_range(filter: Range) -> Self {
        Filter {
            has_filter: true,
            param: FilterParam::Discard(filter.from),
            filter: vec![filter.to],
            captured_buf_len: 0,
            advanced_by: 0,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(filter))]
    #[allow(dead_code)]
    pub fn new_with_edit_list(mut filter: Option<Vec<u64>>) -> Self {
        Filter {
            has_filter: filter.is_some(),
            param: filter
                .as_mut()
                .map(|f| f.pop().map(|e| FilterParam::Discard(e)))
                .flatten()
                .unwrap_or(FilterParam::None),
            filter: filter.unwrap_or_default(),
            captured_buf_len: 0,
            advanced_by: 0,
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) | Ok(Message::ShouldFlush) => return Ok(true),
                    Ok(Message::EditList(filter)) => {
                        self.has_filter = true;
                        self.filter = filter;
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

    fn next_param(&mut self) {
        let next = self.filter.pop();
        match (&self.param, next) {
            (FilterParam::Discard(_), Some(next)) => {
                self.param = FilterParam::Keep(next);
            }
            (FilterParam::Keep(_), Some(next)) => {
                self.param = FilterParam::Discard(next);
            }
            (FilterParam::None, Some(next)) => {
                self.param = FilterParam::Discard(next);
            }
            (_, None) => {
                self.param = FilterParam::None;
                self.has_filter = false;
            }
        }
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

        if !self.has_filter {
            self.process_messages()?;
        }

        // If bytes are present in the buffer
        if !buf.is_empty() {
            if !self.has_filter {
                warn!("No filter set, passing through");
                return Ok(());
            }

            let mut keep_buf = BytesMut::with_capacity(buf.len());
            loop {
                match &mut self.param {
                    FilterParam::Discard(bytes) => {
                        if buf.len() < *bytes as usize {
                            buf.clear();
                            *bytes -= buf.len() as u64;
                            break;
                        } else {
                            buf.advance(*bytes as usize);
                            self.next_param();
                        }
                    }
                    FilterParam::Keep(bytes) => {
                        if buf.len() < *bytes as usize {
                            *bytes -= buf.len() as u64;
                            if !keep_buf.is_empty() {
                                keep_buf.put(buf.split());
                            }
                            break;
                        } else {
                            keep_buf.put(buf.split_to(*bytes as usize));
                            self.next_param();
                        }
                    }
                    FilterParam::None => return Ok(()),
                }
            }
            if !keep_buf.is_empty() {
                buf.clear();
                buf.put(keep_buf);
            }
        }

        if let Ok(finished) = self.process_messages() {
            if finished {
                if let Some(notifier) = &self.notifier {
                    notifier.send_next(
                        self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                        Message::Finished,
                    )?;
                }
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
