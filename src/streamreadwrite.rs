use crate::notifications::Message;
use crate::transformer::{Category, Notifier, ReadWriter, Sink, Transformer};
use crate::transformers::writer_sink::WriterSink;
use anyhow::anyhow;
use anyhow::Result;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use tokio::io::{AsyncWrite, BufWriter};

pub struct ArunaStreamReadWriter<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>> + Unpin,
> {
    input_stream: R,
    transformers: Vec<Box<dyn Transformer>>,
    sink: Box<dyn Sink + 'a>,
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>> + Unpin,
    > ArunaStreamReadWriter<'a, R>
{
    pub fn new_with_sink<T: Sink + Send + 'a>(input_stream: R, transformer: T) -> Self {
        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(transformer),
            transformers: Vec::new(),
        }
    }

    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + 'a>(input_stream: R, writer: W) -> Self {
        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            transformers: Vec::new(),
        }
    }

    pub fn add_transformer<T: Sink + Send + 'a>(&mut self, mut transformer: T) -> Self {
        transformer.set_id(self.transformers.len());
        transformer.add_root(self);
        self.transformers.push(transformer)
    }
}

#[async_trait::async_trait]
impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>> + Unpin,
    > Notifier for ArunaStreamReadWriter<'a, R>
{
    async fn notify(&self, target: u64, message: Message) -> Result<Message> {
        todo!();
    }
    async fn get_next_id_of_type(&self, target: Category) -> Option<u64> {
        todo!();
    }
}

#[async_trait::async_trait]
impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>> + Unpin,
    > ReadWriter for ArunaStreamReadWriter<'a, R>
{
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut bytes_read;
        let mut data = Bytes::new();

        loop {
            if let Some(b) = self.input_stream.next().await {
                data = b.map_err(|_| anyhow!("Received error in stream"))?;
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
