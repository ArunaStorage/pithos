use crate::transformer::{FileContext, TransformerType};

#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileMessage {
    pub context: FileContext,
    pub is_last: bool,
    pub should_flush: bool,
}
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FooterData {
    pub chunks: Vec<u8>,
}
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProbeBroadcast {
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Message {
    pub target: TransformerType,
    pub data: MessageData,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageData {
    NextFile(FileMessage),
    Footer(FooterData),
    ProbeBroadcast(ProbeBroadcast),
}

#[derive(Clone, Default)]
pub enum Response {
    #[default]
    Ok,
}
