use crate::notifications::Message;
use crate::transformer::{Category, Notifier, ReadWriter, Sink, Transformer};
use crate::transformers::writer_sink::WriterSink;
use anyhow::Result;
use anyhow::{anyhow, bail};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use tokio::io::{AsyncWrite, BufWriter};

pub struct ArunaStreamReadWriter<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>> + Unpin,
> {
    input_stream: R,
    transformers: Vec<Box<dyn Transformer + Send + Sync>>,
    sink: Box<dyn Transformer + 'a + Send + Sync>,
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > ArunaStreamReadWriter<'a, R>
{
    pub fn new_with_sink<T: Transformer + Sink + Send + Sync + 'a>(
        input_stream: R,
        transformer: T,
    ) -> Self {
        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(transformer),
            transformers: Vec::new(),
        }
    }

    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + Sync + 'a>(
        input_stream: R,
        writer: W,
    ) -> Self {
        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            transformers: Vec::new(),
        }
    }

    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(
        mut self,
        mut transformer: T,
    ) -> Self {
        transformer.set_id(self.transformers.len() as u64);
        transformer.add_root(Box::new(self));
        self.transformers.push(Box::new(transformer));
        self
    }
}

#[async_trait::async_trait]
impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > Notifier for ArunaStreamReadWriter<'a, R>
{
    async fn notify(&self, target: u64, message: Message) -> Result<Message> {
        bail!("error")
    }
    async fn get_next_id_of_type(&self, target: Category) -> Option<u64> {
        todo!();
    }
}

#[async_trait::async_trait]
impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > ReadWriter for ArunaStreamReadWriter<'a, R>
{
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut bytes_read;
        let mut data = BytesMut::new();

        loop {
            if let Some(b) = self.input_stream.next().await {
                data.put(b.map_err(|_| anyhow!("Received error in stream"))?);
            };
            bytes_read = data.len();
            if bytes_read != 0 {
                self.sink.process_bytes(&mut data, false).await?;
            } else if self.sink.process_bytes(&mut data, true).await? {
                break;
            }

            log::debug!("StreamReadWriter: Processed {}", bytes_read);
        }
        Ok(())
    }
}
