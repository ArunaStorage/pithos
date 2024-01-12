use crate::transformer::{FileContext, TransformerType};
use async_channel::Sender;

#[non_exhaustive]
pub enum HashType {
    Sha1,
    Md5,
    Other(String),
}

#[non_exhaustive]
pub enum Message {
    Completed,
    Finished,
    FileContext(FileContext),
    Hash((HashType, String)),
    Metadata((Option<Vec<u8>>, String)), // Optional different Key, JSON Metadata value
    SizeInfo(u64),
    Compression(bool),
    EditList(Vec<u64>),
    Blocklist(Vec<u8>),
    ShouldFlush,
    Skip,
    Custom((String, Vec<u8>)),
}

pub struct Notifier {
    read_writer: Sender<Message>,
    notifiers: Vec<(TransformerType, Sender<Message>)>,
}

impl Notifier {
    pub fn send_next(&self, idx: usize, message: Message) -> anyhow::Result<()> {
        if idx + 1 < self.notifiers.len() {
            self.notifiers[idx + 1].1.try_send(message)?;
        }
        Ok(())
    }
    pub fn send_type(&self, trans_type: TransformerType) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn send_read_writer(&self, message: Message) -> anyhow::Result<()> {
        self.read_writer.try_send(message)?;
        Ok(())
    }
}
