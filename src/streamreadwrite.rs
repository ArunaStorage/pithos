use crate::notifications::Message;
use crate::transformer::{ReadWriter, Sink, Transformer};
use crate::transformers::writer_sink::WriterSink;
use anyhow::{anyhow, Result};
use async_channel::{Receiver, Sender};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use tokio::io::{AsyncWrite, BufWriter};

pub struct ArunaStreamReadWriter<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
        + Unpin
        + Send
        + Sync,
> {
    input_stream: R,
    transformers: Vec<Box<dyn Transformer + Send + Sync + 'a>>,
    sink: Box<dyn Sink + Send + Sync + 'a>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
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
        let (sx, rx) = async_channel::unbounded();

        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(transformer),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
        }
    }

    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + Sync + 'a>(
        input_stream: R,
        writer: W,
    ) -> Self {
        let (sx, rx) = async_channel::unbounded();

        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
        }
    }

    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(
        mut self,
        mut transformer: T,
    ) -> ArunaStreamReadWriter<'a, R> {
        transformer.add_sender(self.sender.clone());
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
    > ReadWriter for ArunaStreamReadWriter<'a, R>
{
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut read_buf = BytesMut::with_capacity(65_536 * 2);
        let mut finished = false;
        loop {
            if read_buf.is_empty() {
                // TODO: UPDATE finished
                read_buf.put(
                    self.input_stream
                        .next()
                        .await
                        .ok_or_else(|| anyhow!("Returned None"))?
                        .map_err(|_| anyhow!("Returned None"))?,
                );
            }
            for t in self.transformers.iter_mut() {
                match t.process_bytes(&mut read_buf, finished).await? {
                    true => {}
                    false => finished = false,
                };
            }
            self.sink.process_bytes(&mut read_buf, finished).await?;
            if read_buf.is_empty() & finished {
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
