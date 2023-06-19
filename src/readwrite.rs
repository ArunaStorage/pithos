use crate::notifications::{FileMessage, Message};
use crate::transformer::{FileContext, ReadWriter, Sink, Transformer, TransformerType};
use crate::transformers::writer_sink::WriterSink;
use anyhow::Result;
use async_channel::{Receiver, Sender};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};

pub struct ArunaReadWriter<'a, R: AsyncRead + Unpin> {
    reader: BufReader<R>,
    transformers: Vec<(TransformerType, Box<dyn Transformer + Send + Sync + 'a>)>,
    sink: Box<dyn Transformer + Send + Sync + 'a>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    size_counter: usize,
    current_file_context: Option<(FileContext, bool)>,
    next_file_context: Option<(FileContext, bool)>,
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
            size_counter: 0,
            current_file_context: None,
            next_file_context: None,
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
            size_counter: 0,
            current_file_context: None,
            next_file_context: None,
        }
    }

    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(
        mut self,
        mut transformer: T,
    ) -> Self {
        transformer.add_sender(self.sender.clone());

        self.transformers
            .push((transformer.get_type(), Box::new(transformer)));
        self
    }
}

#[async_trait::async_trait]
impl<'a, R: AsyncRead + Unpin + Send + Sync> ReadWriter for ArunaReadWriter<'a, R> {
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut read_buf = BytesMut::with_capacity(65_536 * 2);
        let mut finished;
        let mut maybe_msg: Option<Message> = None;
        let mut read_bytes: usize;
        loop {
            read_bytes = self.reader.read_buf(&mut read_buf).await?;

            if let Some((context, is_last)) = &self.current_file_context {
                self.size_counter += read_bytes;

                if self.size_counter > context.file_size as usize {}
            }

            finished = read_buf.is_empty() && read_bytes == 0;

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
            if read_buf.is_empty() && finished {
                break;
            }
        }
        Ok(())
    }

    async fn announce_all(&mut self, mut message: Message) -> Result<()> {
        message.target = TransformerType::All;
        for (_, trans) in self.transformers.iter_mut() {
            trans.notify(&message).await?;
        }
        Ok(())
    }

    async fn next_context(&mut self, context: FileContext, is_last: bool) -> Result<()> {
        if self.current_file_context.is_none() {
            self.current_file_context = Some((context.clone(), is_last));
            self.announce_all(Message {
                target: TransformerType::All,
                data: crate::notifications::MessageData::NextFile(FileMessage { context }),
            })
            .await?;
        } else {
            self.next_file_context = Some((context, is_last))
        }
        Ok(())
    }
}
