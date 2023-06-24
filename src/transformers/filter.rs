use crate::helpers::footer_parser::Range;
use crate::transformer::{Transformer, TransformerType};
use anyhow::Result;
use bytes::Buf;

pub struct Filter {
    counter: usize,
    filter: Range,
    captured_buf_len: usize,
    advanced_by: usize,
}

impl Filter {
    #[allow(dead_code)]
    pub fn new(filter: Range) -> Self {
        Filter {
            counter: 0,
            filter,
            captured_buf_len: 0,
            advanced_by: 0,
        }
    }
}

#[async_trait::async_trait]
impl Transformer for Filter {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, _finished: bool) -> Result<bool> {
        self.captured_buf_len = buf.len();
        self.advanced_by = 0;
        if !buf.is_empty() {
            if ((self.counter + self.captured_buf_len) as u64) > self.filter.from {
                if self.counter > self.filter.from as usize {
                    buf.clear();
                } else {
                    self.advanced_by = self.filter.from as usize - self.counter;
                    buf.advance(self.advanced_by);
                }
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
        Ok(true)
    }

    #[inline]
    fn get_type(&self) -> TransformerType {
        TransformerType::Filter
    }
}
