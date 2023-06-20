use std::mem;
use std::time::Duration;
use std::time::SystemTime;

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
    head_size: usize,
    current_file: usize,
}

impl TryFrom<FileContext> for Header {
    type Error = anyhow::Error;

    fn try_from(value: FileContext) -> Result<Self> {
        let mut header = Header::new_gnu();

        let path = match value.file_path {
            Some(p) => p + &value.file_name,
            None => value.file_name,
        };
        header.set_path(path)?;
        header.set_mode(value.mode.unwrap_or_else(|| 0o644));
        header.set_mtime(value.mtime.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs()
        }));
        header.set_uid(value.gid.unwrap_or_else(|| 1000));
        header.set_gid(value.gid.unwrap_or_else(|| 1000));
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
            head_size: 0,
            current_file: 0,
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
        }
        self.current_file += buf.len();

        if self.first {
            if let Some(header) = &self.header {
                self.head_size = header.size()? as usize;
                let temp = buf.split();
                buf.put(header.as_bytes().as_slice());
                buf.put(temp);
                self.first = false;
            }
        }
        if self.current_file == self.head_size {
            // Add padding
            let pad = vec![0u8; 512 - self.current_file % 512];
            buf.put(pad.as_ref());
            self.header = mem::take(&mut self.next_header);
            if let Some(head) = &self.header {
                buf.put(head.as_bytes().as_slice());
                self.head_size = head.size()? as usize;
            }
            self.current_file = 0;
        }

        if finished && !self.finished {
            buf.put([0u8; 1024].as_slice());
            self.finished = true;
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
                    self.finished = false;
                }
                _ => (),
            }
        }

        Ok(Response::Ok)
    }
}
