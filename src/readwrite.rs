use crate::notifications::Message;
use crate::transformer::{ReadWriter, Sink, Transformer};
use crate::transformers::writer_sink::WriterSink;
use anyhow::Result;
use async_channel::{Receiver, Sender};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};

pub struct ArunaReadWriter<'a, R: AsyncRead + Unpin> {
    reader: BufReader<R>,
    transformers: Vec<Box<dyn Transformer + Send + Sync + 'a>>,
    sink: Box<dyn Transformer + Send + Sync + 'a>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
}

impl<'a, R: AsyncRead + Unpin> ArunaReadWriter<'a, R> {
    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + Sync + 'a>(
        reader: R,
        writer: W,
    ) -> ArunaReadWriter<'a, R> {
        let (sx, rx) = async_channel::unbounded();
        ArunaReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
        }
    }

    pub fn new_with_sink<T: Transformer + Sink + Send + Sync + 'a>(
        reader: R,
        transformer: T,
    ) -> ArunaReadWriter<'a, R> {
        let (sx, rx) = async_channel::unbounded();

        ArunaReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(transformer),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
        }
    }

    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(
        mut self,
        mut transformer: T,
    ) -> Self {
        transformer.add_sender(self.sender.clone());
        self.transformers.push(Box::new(transformer));
        self
    }
}

#[async_trait::async_trait]
impl<'a, R: AsyncRead + Unpin + Send + Sync> ReadWriter for ArunaReadWriter<'a, R> {
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut read_buf = BytesMut::with_capacity(65_536 * 2);
        let mut should_continue = false;
        loop {
            if read_buf.is_empty() {
                self.reader.read_buf(&mut read_buf).await?;
            }
            for t in self.transformers.iter_mut() {
                match t.process_bytes(&mut read_buf, should_continue).await? {
                    true => {}
                    false => should_continue = true,
                };
            }
            self.sink
                .process_bytes(&mut read_buf, should_continue)
                .await?;
            if read_buf.is_empty() & !should_continue {
                break;
            }
        }
        Ok(())
    }

    async fn announce_all(&mut self, message: Message) -> Result<()> {
        for trans in self.transformers.iter_mut() {
            trans.notify(message.clone()).await?;
        }
        Ok(())
    }
}
