use crate::helpers::footer_parser::Range;
use crate::notifications::Message;
use crate::transformer::Transformer;
use anyhow::Result;
use bytes::Buf;

pub struct Filter {
    counter: usize,
    filter: Range,
    captured_buf_len: usize,
    advanced_by: usize,
    id: u64,
}

impl Filter {
    #[allow(dead_code)]
    pub fn new(filter: Range) -> Self {
        Filter {
            counter: 0,
            filter,
            captured_buf_len: 0,
            advanced_by: 0,
            id: 0,
        }
    }
}

#[async_trait::async_trait]
impl Transformer for Filter {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
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
        Ok(true)
    }
    async fn notify(&mut self, message: Message) -> Result<Message> {
        Ok(Message::default())
    }
    fn set_id(&mut self, id: u64) {
        self.id = id
    }
    fn get_id(&self) -> u64 {
        self.id
    }
}
