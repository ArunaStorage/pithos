#[derive(Clone, Default)]
pub struct Filemessage {}
#[derive(Clone, Default)]
pub struct FooterData {
    pub chunks: Vec<u8>,
}
#[derive(Clone, Default)]
pub struct ProbeBroadcast {
    pub message: String,
}

#[derive(Clone)]
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
