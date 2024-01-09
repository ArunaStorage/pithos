use crate::transformer::{Transformer, TransformerType};
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender};
use digest::{Digest, FixedOutputReset};
use tracing::error;

pub struct HashingTransformer<T: Digest + Send + FixedOutputReset> {
    hasher: T,
    sender: Sender<String>,
}

impl<T> HashingTransformer<T>
where
    T: Digest + Send + Sync + FixedOutputReset,
{
    #[tracing::instrument(level = "trace", skip(hasher))]
    #[allow(dead_code)]
    pub fn new(hasher: T) -> (HashingTransformer<T>, Receiver<String>) {
        let (sender, receiver) = async_channel::bounded(1);
        (HashingTransformer { hasher, sender }, receiver)
    }
}

#[async_trait::async_trait]
impl<T> Transformer for HashingTransformer<T>
where
    T: Digest + Send + Sync + FixedOutputReset,
{
    #[tracing::instrument(level = "trace", skip(self, buf, finished))]
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        _: bool,
    ) -> Result<bool> {
        Digest::update(&mut self.hasher, &buf);

        if finished && buf.is_empty() {
            match self
                .sender
                .try_send(format!("{}", hex::encode(self.hasher.finalize_reset())))
            {
                Ok(_) => {}
                Err(e) => match e {
                    async_channel::TrySendError::Full(_) => {}
                    async_channel::TrySendError::Closed(_) => {
                        error!("Sending in closed channel");
                        return Err(anyhow!("HashingTransformer: Channel closed"))
                    }
                },
            }
        }
        Ok(true)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn get_type(&self) -> TransformerType {
        TransformerType::Hashing
    }
}
