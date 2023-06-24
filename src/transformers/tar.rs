use crate::notifications::Message;
use crate::notifications::Response;
use crate::transformer::FileContext;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::bail;
use anyhow::Result;
use bytes::BufMut;
use std::time::Duration;
use std::time::SystemTime;
use tar::Header;

pub struct TarEnc {
    header: Option<Header>,
    padding: usize,
    finished: bool,
    init: bool,
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
        header.set_mode(value.mode.unwrap_or(0o644));
        header.set_mtime(value.mtime.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs()
        }));
        header.set_uid(value.gid.unwrap_or(1000));
        header.set_gid(value.gid.unwrap_or(1000));
        header.set_size(value.file_size);
        header.set_cksum();
        Ok(header)
    }
}

impl TarEnc {
    pub fn new() -> TarEnc {
        TarEnc {
            header: None,
            padding: 0,
            finished: false,
            init: true,
        }
    }
}

impl Default for TarEnc {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transformer for TarEnc {
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        _: bool,
    ) -> Result<bool> {
        if let Some(header) = &self.header {
            let temp = buf.split();
            if !self.init {
                buf.put(vec![0u8; self.padding].as_ref());
            } else {
                self.init = false;
            }
            buf.put(header.as_bytes().as_slice());
            buf.put(temp);
            self.header = None;
        }

        if finished && !self.finished {
            buf.put(vec![0u8; self.padding].as_ref());
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
            if let crate::notifications::MessageData::NextFile(nfile) = &message.data {
                if self.header.is_none() {
                    self.padding = 512 - nfile.context.file_size as usize % 512;
                    self.header = Some(TryInto::<Header>::try_into(nfile.context.clone())?);
                } else {
                    bail!("[TAR] A Header is still present")
                }
                self.finished = false;
            }
        }

        Ok(Response::Ok)
    }
}
