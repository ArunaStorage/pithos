use crate::notifications::Message;
use crate::notifications::Notifier;
use crate::structs::FileContext;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use async_channel::Receiver;
use async_channel::Sender;
use async_channel::TryRecvError;
use bytes::BufMut;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tar::Header;
use tracing::error;

pub struct TarEnc {
    header: Option<Header>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
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

// File1: 0..512+file1_len (HEADER + FILE)
// File2: 512+file1_len+1..

impl TarEnc {
    #[tracing::instrument(level = "trace", skip())]
    pub fn new() -> TarEnc {
        TarEnc {
            header: None,
            notifier: None,
            msg_receiver: None,
            idx: None,
            padding: 0,
            finished: false,
            init: true,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<(bool, bool)> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::FileContext(ctx)) => {
                        if self.header.is_none() {
                            if ctx.is_dir || ctx.is_symlink {
                                self.padding = 0;
                            } else {
                                self.padding = 512 - ctx.file_size as usize % 512;
                            }
                            self.header = Some(TryInto::<Header>::try_into(ctx.clone())?);
                        } else {
                            error!("A Header is still present");
                            bail!("[TAR] A Header is still present")
                        }
                    }
                    Ok(Message::ShouldFlush) => return Ok((true, false)),
                    Ok(Message::Finished) => return Ok((false, true)),
                    Ok(_) => {}
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Closed) => {
                        error!("Message receiver closed");
                        return Err(anyhow!("Message receiver closed"));
                    }
                }
            }
        }
        Ok((false, false))
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
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::TarEncoder, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        let Ok((should_flush, finished)) = self.process_messages() else {
            return Err(anyhow!("Error processing messages"));
        };

        if should_flush {
            if self.padding > 0 {
                buf.put(vec![0u8; self.padding].as_ref());
            }
            self.padding = 0;
            return Ok(());
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
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}
