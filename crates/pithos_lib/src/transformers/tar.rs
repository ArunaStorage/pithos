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
use tracing::debug;
use tracing::error;

pub struct TarEnc {
    header: Option<Header>,
    padding: usize,
    finished: bool,
    init: bool,
}

impl TryFrom<FileContext> for Header {
    type Error = anyhow::Error;

    #[tracing::instrument(level = "trace", skip(value))]
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
    #[tracing::instrument(level = "trace", skip())]
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
    #[tracing::instrument(level = "trace", skip())]
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transformer for TarEnc {
    #[tracing::instrument(level = "trace", skip(self, buf, finished, should_flush))]
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        should_flush: bool,
    ) -> Result<bool> {
        if should_flush {
            if self.padding > 0 {
                buf.put(vec![0u8; self.padding].as_ref());
            }
            self.padding = 0;
            return Ok(finished);
        }
        if let Some(header) = &self.header {
            let temp = buf.split();
            if self.init {
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

    #[tracing::instrument(level = "trace", skip(self))]
    fn get_type(&self) -> TransformerType {
        TransformerType::TarEncoder
    }

    #[tracing::instrument(level = "trace", skip(self, message))]
    async fn notify(&mut self, message: &Message) -> Result<Response> {
        if message.target == TransformerType::All {
            if let crate::notifications::MessageData::NextFile(nfile) = &message.data {
                debug!("received next file message");
                if self.header.is_none() {
                    if nfile.context.is_dir || nfile.context.is_symlink {
                        self.padding = 0;
                    } else {
                        self.padding = 512 - nfile.context.file_size as usize % 512;
                    }
                    self.header = Some(TryInto::<Header>::try_into(nfile.context.clone())?);
                } else {
                    error!("A Header is still present");
                    bail!("[TAR] A Header is still present")
                }
                self.finished = false;
            }
        }

        Ok(Response::Ok)
    }
}
