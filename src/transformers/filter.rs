use anyhow::anyhow;
use anyhow::Result;
use bytes::Buf;

use crate::helpers::footer_parser::Range;
use crate::transformer::AddTransformer;
use crate::transformer::Notifications;
use crate::transformer::Transformer;

pub struct Filter<'a> {
    counter: usize,
    filter: Range,
    captured_buf_len: usize,
    advanced_by: usize,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> Filter<'a> {
    #[allow(dead_code)]
    pub fn new(filter: Range) -> Filter<'a> {
        Filter {
            counter: 0,
            filter,
            captured_buf_len: 0,
            advanced_by: 0,
            next: None,
        }
    }
}

impl<'a> AddTransformer<'a> for Filter<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for Filter<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        self.captured_buf_len = buf.len();
        self.advanced_by = 0;
        if !buf.is_empty() {
            if ((self.counter + self.captured_buf_len) as u64) > self.filter.from {
                self.advanced_by = self.filter.from as usize - self.counter;
                buf.advance(self.advanced_by);
            } else {
                buf.clear();
            }

            if self.counter as u64 > self.filter.to {
                buf.clear();
            } else if self.counter as u64 + self.captured_buf_len as u64 > self.filter.to {
                buf.truncate(self.filter.to as usize - self.advanced_by - self.counter);
            }
        }

        self.counter += self.captured_buf_len;

        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
            next.process_bytes(buf, finished).await
        } else {
            Err(anyhow!(
                "This decrypter is designed to always contain a 'next'"
            ))
        }
    }
    async fn notify(&mut self, notes: &mut Vec<Notifications>) -> Result<()> {
        if let Some(next) = &mut self.next {
            next.notify(notes).await?
        }
        Ok(())
    }
}
