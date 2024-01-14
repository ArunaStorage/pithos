use crate::notifications::{HashType, Message, Notifier};
use crate::transformer::{Transformer, TransformerType};
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender, TryRecvError};
use digest::{Digest, FixedOutputReset};
use std::sync::Arc;
use tracing::error;

pub struct HashingTransformer<T: Digest + Send + FixedOutputReset> {
    hasher: T,
    hasher_type: String,
    idx: Option<usize>,
    msg_receiver: Option<Receiver<Message>>,
    notifier: Option<Arc<Notifier>>,
}

impl<T> HashingTransformer<T>
where
    T: Digest + Send + Sync + FixedOutputReset,
{
    #[tracing::instrument(level = "trace", skip(hasher))]
    #[allow(dead_code)]
    pub fn new(hasher: T, hasher_type: String) -> HashingTransformer<T> {
        HashingTransformer {
            hasher,
            hasher_type,
            idx: None,
            msg_receiver: None,
            notifier: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) | Ok(Message::ShouldFlush) => return Ok(true),
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
        Ok(false)
    }
}

#[async_trait::async_trait]
impl<T> Transformer for HashingTransformer<T>
where
    T: Digest + Send + Sync + FixedOutputReset,
{
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::Hashing, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        Digest::update(&mut self.hasher, &buf);

        if buf.is_empty() {
            let Ok(finished) = self.process_messages() else {
                return Err(anyhow!("HashingTransformer: Error processing messages"));
            };

            if finished {
                if let Some(notifier) = &self.notifier {
                    let finished_hash = hex::encode(self.hasher.finalize_reset()).to_string();
                    let hashertype = match self.hasher_type.as_str() {
                        "sha1" => HashType::Sha1,
                        "md5" => HashType::Md5,
                        a => HashType::Other(a.to_string()),
                    };
                    notifier.send_all_type(
                        TransformerType::FooterGenerator,
                        Message::Hash((hashertype.clone(), finished_hash.clone())),
                    )?;
                    notifier.send_read_writer(Message::Hash((hashertype, finished_hash)))?;
                    notifier.send_next(
                        self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                        Message::Finished,
                    )?;
                }
            }
            return Ok(());
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
