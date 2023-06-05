#[derive(Clone, Default)]
pub struct Message {
    pub recipient: u64,
    pub info: Option<Vec<u8>>,
    pub message_type: MessageType,
}

pub enum MessageType {
    Message,
    Response,
}

impl Message {
    pub fn get_data(self) -> Option<Vec<u8>> {
        self.info
    }
}
