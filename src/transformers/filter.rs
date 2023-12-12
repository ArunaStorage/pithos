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
    #[tracing::instrument(level = "trace", skip(filter))]
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
    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, _: bool, _: bool) -> Result<bool> {
        self.captured_buf_len = buf.len();
        self.advanced_by = 0;

        // If bytes are present in the buffer
        if !buf.is_empty() {
            // If counter + incoming bytes are larger than lower limit
            //   -> Advance buffer to lower limit
            if ((self.counter + self.captured_buf_len) as u64) > self.filter.from {
                self.advanced_by = self.filter.from as usize - self.counter;
                buf.advance(self.advanced_by);
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
        Ok(true)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    #[inline]
    fn get_type(&self) -> TransformerType {
        TransformerType::Filter
    }
}
