use crate::notifications::Message;
use crate::notifications::Response;
use crate::transformer::FileContext;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use bytes::BufMut;
use tar::Header;

pub struct TarEnc {
    header: Option<Header>,
    next_header: Option<Header>,
    first: bool,
    finished: bool,
}

impl TryFrom<FileContext> for Header {
    type Error = anyhow::Error;

    fn try_from(value: FileContext) -> Result<Self> {
        let mut header = Header::new_ustar();

        let path = match value.file_path {
            Some(p) => p + &value.file_name,
            None => value.file_name,
        };
        header.set_path(path)?;
        header.set_size(value.file_size);
        header.set_cksum();
        Ok(header)
    }
}

impl TarEnc {
    pub fn new() -> TarEnc {
        TarEnc {
            header: None,
            next_header: None,
            first: true,
            finished: false,
        }
    }
}

#[async_trait::async_trait]
impl Transformer for TarEnc {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        // This is forbidden! A tar transformer needs all information to build a header before data is received.
        if buf.len() != 0 && self.header.is_none() {
            return Err(anyhow!(
                "[TAR] A tar transformer needs at least one header before data is received."
            ));
        } else if buf.len() != 0 && self.first {
            if let Some(header) = &self.header {
                let temp = buf.split();
                buf.put(header.as_bytes().as_slice());
                buf.put(temp);
                if self.next_header.is_some() {
                    self.header = self.next_header.clone();
                    self.next_header = None;
                } else {
                    self.header = None;
                }
                self.first = false;
                return Ok(true);
            }
        }

        if finished {
            if let Some(head) = &self.header {
                let temp = buf.split();
                buf.put(head.as_bytes().as_slice());
                buf.put(temp);
                if self.next_header.is_some() {
                    self.header = self.next_header.clone();
                    self.next_header = None;
                } else {
                    self.header = None;
                }
            } else {
                self.finished = true
            }
        }
        Ok(self.finished)
    }

    fn get_type(&self) -> TransformerType {
        TransformerType::TarEncoder
    }

    async fn notify(&mut self, message: &Message) -> Result<Response> {
        if message.target == TransformerType::All {
            match &message.data {
                crate::notifications::MessageData::NextFile(nfile) => {
                    if self.header.is_none() {
                        self.header = Some(TryInto::<Header>::try_into(nfile.context.clone())?)
                    } else {
                        if self.next_header.is_some() {
                            bail!("[TAR] Current + next header already used")
                        }
                        self.next_header = Some(TryInto::<Header>::try_into(nfile.context.clone())?)
                    }
                    self.finished = false
                }
                _ => (),
            }
        }

        Ok(Response::Ok)
    }
}
