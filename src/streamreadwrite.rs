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
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + 'static>>> + Unpin + Send + Sync,
> {
    input_stream: R,
    transformers: Vec<Box<dyn Transformer + Send + Sync>>,
    sink: Box<dyn Transformer + 'a + Send + Sync>,
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + 'static>>> + Unpin + Send + Sync,
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

    pub fn new_with_writer<W: AsyncWrite + Unpin + 'a + Send + Sync>(
        input_stream: R,
        writer: W,
    ) -> Self {
        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            transformers: Vec::new(),
        }
    }

    pub fn add_transformer<T: Transformer + 'a + Send + Sync + 'static>(
        mut self,
        mut transformer: T,
    ) -> Self {
        transformer.set_id(self.transformers.len() as u64);
        self.transformers.push(Box::new(transformer));
        self
    }
}

#[async_trait::async_trait]
impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + 'static>>> + Unpin + Send + Sync,
    > ReadWriter for ArunaStreamReadWriter<'a, R>
{
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut read_buf = BytesMut::with_capacity(65_536);

        loop {
            read_buf.put(self.input_stream.next().await.unwrap().unwrap());
            if read_buf.len() != 0 {
                self.sink.process_bytes(&mut read_buf, false).await?;
            } else if self.sink.process_bytes(&mut read_buf, true).await? {
                break;
            }
        }
        Ok(())
    }
}
