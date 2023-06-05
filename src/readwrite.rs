use crate::notifications::Message;
use crate::transformer::{Category, Notifier, ReadWriter, Sink, Transformer};
use crate::transformers::writer_sink::WriterSink;
use anyhow::Result;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};

pub struct ArunaReadWriter<'a, R: AsyncRead + Unpin> {
    reader: BufReader<R>,
    transformers: Vec<Box<dyn Transformer>>,
    sink: Box<dyn Sink + 'a>,
}

impl<'a, R: AsyncRead + Unpin> ArunaReadWriter<'a, R> {
    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + 'a>(
        reader: R,
        writer: W,
    ) -> ArunaReadWriter<'a, R> {
        ArunaReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            transformers: Vec::new(),
        }
    }

    pub fn new_with_sink<T: Sink + Send + 'a>(reader: R, transformer: T) -> ArunaReadWriter<'a, R> {
        ArunaReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(transformer),
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
impl<'a, R: AsyncRead + Unpin> ReadWriter for ArunaReadWriter<'a, R> {
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut bytes_read;
        let mut read_buf = BytesMut::with_capacity(65_536);

        loop {
            bytes_read = self.reader.read_buf(&mut read_buf).await?;
            if bytes_read != 0 {
                self.sink
                    .process_bytes(&mut read_buf.split().freeze(), false)
                    .await?;
            } else if self
                .sink
                .process_bytes(&mut read_buf.split().freeze(), true)
                .await?
            {
                break;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<'a, R: AsyncRead + Unpin> Notifier for ArunaReadWriter<'a, R> {
    async fn notify(&self, target: u64, message: Message) -> Result<Message> {
        todo!();
    }
    async fn get_next_id_of_type(&self, target: Category) -> Option<u64> {
        todo!();
    }
}
