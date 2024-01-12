use crate::notifications::Message;
use crate::notifications::Notifier;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use async_channel::Sender;
use async_compression::tokio::write::GzipEncoder;
use std::sync::Arc;

const RAW_FRAME_SIZE: usize = 5_242_880;

pub struct GzipEnc {
    internal_buf: GzipEncoder<Vec<u8>>,
    notifier: Option<Arc<Notifier>>,
    idx: Option<usize>,
    size_counter: usize,
}

impl GzipEnc {
    #[tracing::instrument(level = "trace", skip())]
    #[allow(dead_code)]
    pub fn new() -> Self {
        GzipEnc {
            internal_buf: GzipEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE)),
            idx: None,
            notifier: None,
            size_counter: 0,
        }
    }
}

impl Default for GzipEnc {
    #[tracing::instrument(level = "trace", skip())]
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transformer for GzipEnc {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::GzipCompressor, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        todo!()
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}
