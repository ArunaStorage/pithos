use crate::notifications::Message;
use crate::transformer::{FileContext, ReadWriter, Sink, Transformer, TransformerType};
use crate::transformers::writer_sink::WriterSink;
use anyhow::Result;
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
    transformers: Vec<(TransformerType, Box<dyn Transformer + Send + Sync + 'a>)>,
    sink: Box<dyn Sink + Send + Sync + 'a>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    current_file_context: Option<(FileContext, bool)>,
    next_file_context: Option<(FileContext, bool)>,
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
            current_file_context: None,
            next_file_context: None,
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
            current_file_context: None,
            next_file_context: None,
        }
    }

    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(
        mut self,
        mut transformer: T,
    ) -> ArunaStreamReadWriter<'a, R> {
        transformer.add_sender(self.sender.clone());
        self.transformers
            .push((transformer.get_type(), Box::new(transformer)));
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
        let mut maybe_msg: Option<Message> = None;
        let mut data;

        loop {
            if read_buf.is_empty() {
                data = self
                    .input_stream
                    .next()
                    .await
                    .unwrap_or_else(|| Ok(Bytes::new()))
                    .unwrap_or_default();
                finished = data.is_empty();
                read_buf.put(data);
            }
            for (ttype, trans) in self.transformers.iter_mut() {
                if let Some(m) = &maybe_msg {
                    if m.target == *ttype {
                        trans.notify(m).await?;
                    }
                } else {
                    maybe_msg = self.receiver.try_recv().ok();
                }
                match trans.process_bytes(&mut read_buf, finished).await? {
                    true => {}
                    false => finished = false,
                };
            }
            match self
                .sink
                .process_bytes(&mut read_buf, finished && self.next_file_context.is_none())
                .await?
            {
                true => {}
                false => finished = false,
            };
            if read_buf.is_empty() & finished {
                break;
            }
        }
        Ok(())
    }
    async fn announce_all(&mut self, message: Message) -> Result<()> {
        for (_, trans) in self.transformers.iter_mut() {
            trans.notify(&message).await?;
        }
        Ok(())
    }

    async fn next_context(&mut self, context: FileContext, is_last: bool) -> Result<()> {
        if self.current_file_context.is_none() {
            self.current_file_context = Some((context, is_last))
        } else {
            self.next_file_context = Some((context, is_last))
        }
        Ok(())
    }
}
