use crate::notifications::{FileMessage, Message};
use crate::transformer::{FileContext, ReadWriter, Sink, Transformer, TransformerType};
use crate::transformers::writer_sink::WriterSink;
use anyhow::{bail, Result};
use async_channel::{Receiver, Sender};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use std::mem;
use tokio::io::{AsyncWrite, BufWriter};
use tracing::{debug, error};

pub struct GenericStreamReadWriter<
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
    size_counter: usize,
    current_file_context: Option<(FileContext, bool)>,
    file_ctx_rx: Option<Receiver<(FileContext, bool)>>,
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > GenericStreamReadWriter<'a, R>
{
    #[tracing::instrument(level = "trace", skip(input_stream, transformer))]
    pub fn new_with_sink<T: Transformer + Sink + Send + Sync + 'a>(
        input_stream: R,
        transformer: T,
    ) -> Self {
        let (sx, rx) = async_channel::unbounded();
        GenericStreamReadWriter {
            input_stream: input_stream,
            sink: Box::new(transformer),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            current_file_context: None,
            file_ctx_rx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(input_stream, writer))]
    pub fn new_with_writer<W: AsyncWrite + Send + Sync + 'a>(input_stream: R, writer: W) -> Self {
        let (sx, rx) = async_channel::unbounded();
        GenericStreamReadWriter {
            input_stream: input_stream,
            sink: Box::new(WriterSink::new(BufWriter::new(Box::pin(writer)))),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            current_file_context: None,
            file_ctx_rx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, transformer))]
    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(
        mut self,
        mut transformer: T,
    ) -> GenericStreamReadWriter<'a, R> {
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
    > ReadWriter for GenericStreamReadWriter<'a, R>
{
    #[tracing::instrument(err, level = "trace", skip(self))]
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut read_buf = BytesMut::with_capacity(65_536 * 2);
        let mut hold_buffer = BytesMut::with_capacity(65536);
        let mut finished;
        let mut maybe_msg: Vec<Message> = vec![];
        let mut data;
        let mut read_bytes: usize = 0;
        let mut next_file = false;
        let mut context_zero_file = false;

        if let Some(rx) = &self.file_ctx_rx {
            let (context, is_last) = rx.try_recv()?;
            if context.is_dir || context.is_symlink {
                context_zero_file = true;
            }
            debug!(?context, ?is_last, "received file context");
            self.current_file_context = Some((context.clone(), is_last));
            self.announce_all(Message {
                target: TransformerType::All,
                data: crate::notifications::MessageData::NextFile(FileMessage { context, is_last }),
            })
            .await?;
        }

        loop {
            if !context_zero_file {
                if hold_buffer.is_empty() {
                    if read_buf.is_empty() {
                        data = self
                            .input_stream
                            .next()
                            .await
                            .unwrap_or_else(|| Ok(Bytes::new()))
                            .unwrap_or_default();
                        read_bytes = data.len();
                        read_buf.put(data);
                    }
                } else if read_buf.is_empty() {
                    mem::swap(&mut hold_buffer, &mut read_buf);
                }
            }

            if let Some((context, is_last)) = &self.current_file_context {
                self.size_counter += read_bytes;
                if self.size_counter > context.input_size as usize
                    && !context.is_dir
                    && !context.is_symlink
                {
                    let mut diff = read_bytes - (self.size_counter - context.input_size as usize);
                    if diff >= context.input_size as usize {
                        diff = context.input_size as usize
                    }
                    hold_buffer = read_buf.split_to(diff);
                    mem::swap(&mut read_buf, &mut hold_buffer);
                    self.size_counter -= context.input_size as usize;
                    next_file = !is_last;
                }
                if context.is_dir || context.is_symlink {
                    next_file = !is_last;
                }
                finished = read_buf.is_empty() && read_bytes == 0 && *is_last;
            } else {
                finished = read_buf.is_empty() && read_bytes == 0;
            }

            for (ttype, trans) in self.transformers.iter_mut() {
                if !maybe_msg.is_empty() {
                    for msg in &maybe_msg {
                        if msg.target == *ttype {
                            trans.notify(msg).await?;
                        }
                    }
                }
                if let Ok(msg) = self.receiver.try_recv() {
                    maybe_msg.push(msg);
                }
                match trans.process_bytes(&mut read_buf, finished, false).await? {
                    true => {}
                    false => finished = false,
                };
            }
            match self
                .sink
                .process_bytes(&mut read_buf, finished, false)
                .await?
            {
                true => {}
                false => finished = false,
            };

            // Announce next file
            if next_file {
                if let Some(rx) = &self.file_ctx_rx {
                    // Perform a flush through all transformers!
                    assert!(read_buf.is_empty());
                    for (_, trans) in self.transformers.iter_mut() {
                        trans.process_bytes(&mut read_buf, finished, true).await?;
                    }
                    self.sink
                        .process_bytes(&mut read_buf, finished, true)
                        .await?;
                    let (context, is_last) = rx.recv().await?;

                    // Empty message queue
                    maybe_msg.clear();

                    // Fetch next file context
                    context_zero_file = context.is_dir || context.is_symlink;
                    self.current_file_context = Some((context.clone(), is_last));
                    self.announce_all(Message {
                        target: TransformerType::All,
                        data: crate::notifications::MessageData::NextFile(FileMessage {
                            context,
                            is_last,
                        }),
                    })
                    .await?;
                    for (_, trans) in self.transformers.iter_mut() {
                        trans.process_bytes(&mut read_buf, finished, false).await?;
                    }
                    self.sink
                        .process_bytes(&mut read_buf, finished, true)
                        .await?;
                }
                if !context_zero_file {
                    next_file = false;
                }
            }

            if read_buf.is_empty() & finished {
                break;
            }
            read_bytes = 0;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, message))]
    async fn announce_all(&mut self, message: Message) -> Result<()> {
        if let Some(notifier) = &self.notifier {
            notifier.send_all(message)?;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, rx))]
    async fn add_file_context_receiver(&mut self, rx: Receiver<(FileContext, bool)>) -> Result<()> {
        if self.file_ctx_rx.is_none() {
            self.file_ctx_rx = Some(rx);
            Ok(())
        } else {
            error!("Overwriting existing receivers is not allowed!");
            bail!("[READ_WRITER] Overwriting existing receivers is not allowed!")
        }
    }
}
