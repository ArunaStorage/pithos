use std::mem;

use crate::notifications::{FileMessage, Message};
use crate::transformer::{FileContext, ReadWriter, Sink, Transformer, TransformerType};
use crate::transformers::writer_sink::WriterSink;
use anyhow::{bail, Result};
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
            size_counter: 0,
            current_file_context: None,
            file_ctx_rx: None,
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
            size_counter: 0,
            current_file_context: None,
            file_ctx_rx: None,
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
        let mut hold_buffer = BytesMut::with_capacity(65536);
        let mut finished;
        let mut maybe_msg: Option<Message> = None;
        let mut data;
        let mut read_bytes: usize = 0;
        let mut next_file = false;

        if let Some(rx) = &self.file_ctx_rx {
            let (context, is_last) = rx.try_recv()?;
            self.current_file_context = Some((context.clone(), is_last));
            self.announce_all(Message {
                target: TransformerType::All,
                data: crate::notifications::MessageData::NextFile(FileMessage {
                    context,
                    is_last,
                    should_flush: false,
                }),
            })
            .await?;
        }

        loop {
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

            if let Some((context, is_last)) = &self.current_file_context {
                self.size_counter += read_bytes;
                if self.size_counter > context.input_size as usize {
                    let mut diff = read_bytes - (self.size_counter - context.input_size as usize);
                    if diff >= context.input_size as usize {
                        diff = context.input_size as usize
                    }
                    hold_buffer = read_buf.split_to(diff);
                    mem::swap(&mut read_buf, &mut hold_buffer);
                    self.size_counter -= context.input_size as usize;
                    next_file = !is_last;
                }
                finished = read_buf.is_empty() && read_bytes == 0 && *is_last;
            } else {
                finished = read_buf.is_empty() && read_bytes == 0;
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
            match self.sink.process_bytes(&mut read_buf, finished).await? {
                true => {}
                false => finished = false,
            };

            // Anounce next file
            if next_file {
                if let Some(rx) = &self.file_ctx_rx {
                    let (context, is_last) = rx.recv().await?;
                    self.current_file_context = Some((context.clone(), is_last));
                    self.announce_all(Message {
                        target: TransformerType::All,
                        data: crate::notifications::MessageData::NextFile(FileMessage {
                            context,
                            is_last,
                            should_flush: true,
                        }),
                    })
                    .await?;

                    // Perform a flush through all transformers!
                    for (_, trans) in self.transformers.iter_mut() {
                        trans.process_bytes(&mut read_buf, finished).await?;
                    }
                    self.sink.process_bytes(&mut read_buf, finished).await?;
                }
                next_file = false;
            }

            if read_buf.is_empty() & finished {
                break;
            }
            read_bytes = 0;
        }
        Ok(())
    }
    async fn announce_all(&mut self, message: Message) -> Result<()> {
        for (_, trans) in self.transformers.iter_mut() {
            trans.notify(&message).await?;
        }
        Ok(())
    }

    async fn add_file_context_receiver(&mut self, rx: Receiver<(FileContext, bool)>) -> Result<()> {
        if self.file_ctx_rx.is_none() {
            self.file_ctx_rx = Some(rx);
            Ok(())
        } else {
            bail!("[READ_WRITER] Overwriting existing receivers is not allowed!")
        }
    }

    // async fn next_context(&mut self, context: FileContext, is_last: bool) -> Result<()> {
    //     if self.current_file_context.is_none() {
    //         self.current_file_context = Some((context.clone(), is_last));
    //         self.announce_all(Message {
    //             target: TransformerType::All,
    //             data: crate::notifications::MessageData::NextFile(FileMessage { context }),
    //         })
    //         .await?;
    //     } else {
    //         self.next_file_context = Some((context, is_last))
    //     }
    //     Ok(())
    // }
}
