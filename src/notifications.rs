#[derive(Clone, Default)]
pub struct Filemessage {}
#[derive(Clone, Default)]
pub struct FooterData {}
#[derive(Clone, Default)]
pub struct ProbeBroadcast {}


#[derive(Clone)]
pub enum Message {
    NextFile(Filemessage),
    Footer(FooterData),
}

#[derive(Clone, Default)]
pub enum Response {
    #[default]
    Ok,
    ProbeBroadcast(ProbeBroadcast),
}