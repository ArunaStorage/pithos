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
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> Filter<'a> {
    #[allow(dead_code)]
    pub fn new(filter: Range) -> Result<Filter<'a>> {
        Ok(Filter {
            counter: 0,
            filter,
            next: None,
        })
    }
}

impl<'a> AddTransformer<'a> for Filter<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for Filter<'_> {
    async fn process_bytes(&mut self, mut buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        // Handle "from"
        if (self.counter as u64) < self.filter.from {
            // If the counter plus the buffer will be greater than "from"
            if ((self.counter + buf.len()) as u64) < self.filter.from {
                buf.clear();
            } else {
                buf.advance((self.counter + buf.len()) - self.filter.from as usize);
            }
        }

        if (self.counter as u64) > self.filter.to {
            // If the counter plus the buffer will be greater than "from"
            if ((self.counter + buf.len()) as u64) > self.filter.to {
                buf.clear();
            } else {
                buf.truncate((self.counter + buf.len()) - self.filter.to as usize);
            }
        }

        self.counter += buf.len();

        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
            next.process_bytes(&mut buf, finished).await
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
