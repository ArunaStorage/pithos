#[derive(Clone)]
pub struct Data {
    pub recipient: String,
    pub info: Option<Vec<u8>>,
}

#[derive(Clone)]
pub enum Notifications {
    Message(Data),
    Response(Data),
}

impl Notifications {
    pub fn get_recipient(&self) -> String {
        match self {
            Notifications::Message(a) => a.recipient.to_string(),
            Notifications::Response(a) => a.recipient.to_string(),
        }
    }
    pub fn get_data(self) -> Data {
        match self {
            Notifications::Message(a) => a,
            Notifications::Response(a) => a,
        }
    }
}
