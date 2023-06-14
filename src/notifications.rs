#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Filemessage {
    
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
pub enum Message {
    NextFile(Filemessage),
    Footer(FooterData),
    ProbeBroadcast(ProbeBroadcast),
}

#[derive(Clone, Default)]
pub enum Response {
    #[default]
    Ok,
}
