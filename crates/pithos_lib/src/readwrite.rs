use std::mem;

use crate::notifications::{FileMessage, Message};
use crate::transformer::{FileContext, ReadWriter, Sink, Transformer, TransformerType};
use crate::transformers::writer_sink::WriterSink;
use anyhow::{bail, Result};
use async_channel::{Receiver, Sender};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};
use tracing::{debug, error};

pub struct PithosReadWriter<'a, R: AsyncRead + Unpin> {
    reader: BufReader<R>,
    transformers: Vec<(TransformerType, Box<dyn Transformer + Send + Sync + 'a>)>,
    sink: Box<dyn Transformer + Send + Sync + 'a>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    size_counter: usize,
    current_file_context: Option<(FileContext, bool)>,
    file_ctx_rx: Option<Receiver<(FileContext, bool)>>,
}

impl<'a, R: AsyncRead + Unpin> PithosReadWriter<'a, R> {
    #[tracing::instrument(level = "trace", skip(reader, writer))]
    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + Sync + 'a>(
        reader: R,
        writer: W,
    ) -> PithosReadWriter<'a, R> {
        let (sx, rx) = async_channel::unbounded();
        PithosReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            current_file_context: None,
            file_ctx_rx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(reader, transformer))]
    pub fn new_with_sink<T: Transformer + Sink + Send + Sync + 'a>(
        reader: R,
        transformer: T,
    ) -> PithosReadWriter<'a, R> {
        let (sx, rx) = async_channel::unbounded();

        PithosReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(transformer),
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
    ) -> Self {
        transformer.add_sender(self.sender.clone());

        self.transformers
            .push((transformer.get_type(), Box::new(transformer)));
        self
    }
}

#[async_trait::async_trait]
impl<'a, R: AsyncRead + Unpin + Send + Sync> ReadWriter for PithosReadWriter<'a, R> {
    #[tracing::instrument(err, level = "trace", skip(self))]
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut read_buf = BytesMut::with_capacity(65_536 * 2);
        let mut hold_buffer = BytesMut::with_capacity(65536);
        let mut finished;
        let mut maybe_msg: Option<Message> = None;
        let mut read_bytes: usize = 0;
        let mut next_file: bool = false;

        if let Some(rx) = &self.file_ctx_rx {
            let (context, is_last) = rx.try_recv()?;
            debug!(?context, ?is_last, "received file context");
            self.current_file_context = Some((context.clone(), is_last));
            self.announce_all(Message {
                target: TransformerType::All,
                data: crate::notifications::MessageData::NextFile(FileMessage { context, is_last }),
            })
            .await?;
        }

        loop {
            if hold_buffer.is_empty() {
                read_bytes = self.reader.read_buf(&mut read_buf).await?;
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

            // Anounce next file
            if next_file {
                if let Some(rx) = &self.file_ctx_rx {
                    // Perform a flush through all transformers!
                    for (_, trans) in self.transformers.iter_mut() {
                        trans.process_bytes(&mut read_buf, finished, true).await?;
                    }
                    self.sink
                        .process_bytes(&mut read_buf, finished, true)
                        .await?;
                    let (context, is_last) = rx.recv().await?;
                    self.current_file_context = Some((context.clone(), is_last));
                    self.announce_all(Message {
                        target: TransformerType::All,
                        data: crate::notifications::MessageData::NextFile(FileMessage {
                            context,
                            is_last,
                        }),
                    })
                    .await?;
                    next_file = false;
                }
            }

            if read_buf.is_empty() && finished {
                break;
            }
            read_bytes = 0;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, message))]
    async fn announce_all(&mut self, mut message: Message) -> Result<()> {
        message.target = TransformerType::All;
        for (_, trans) in self.transformers.iter_mut() {
            trans.notify(&message).await?;
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
