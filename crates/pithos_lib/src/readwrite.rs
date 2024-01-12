use std::mem;
use std::sync::Arc;

use crate::notifications::{Message, Notifier};
use crate::structs::FileContext;
use crate::transformer::{ReadWriter, Sink, Transformer, TransformerType};
use crate::transformers::writer_sink::WriterSink;
use anyhow::{bail, Result};
use async_channel::{Receiver, Sender};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};
use tracing::{debug, error};

pub struct GenericReadWriter<'a, R: AsyncRead + Unpin> {
    reader: BufReader<R>,
    notifier: Option<Arc<Notifier>>,
    transformers: Vec<Box<dyn Transformer + Send + Sync + 'a>>,
    sink: Box<dyn Transformer + Send + Sync + 'a>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    size_counter: usize,
    current_file_context: Option<(FileContext, bool)>,
    external_receiver: Option<Receiver<Message>>,
}

impl<'a, R: AsyncRead + Unpin> GenericReadWriter<'a, R> {
    #[tracing::instrument(level = "trace", skip(reader, writer))]
    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + Sync + 'a>(
        reader: R,
        writer: W,
    ) -> GenericReadWriter<'a, R> {
        let (sx, rx) = async_channel::unbounded();
        GenericReadWriter {
            reader: BufReader::new(reader),
            notifier: None,
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            current_file_context: None,
            external_receiver: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(reader, transformer))]
    pub fn new_with_sink<T: Transformer + Sink + Send + Sync + 'a>(
        reader: R,
        transformer: T,
    ) -> GenericReadWriter<'a, R> {
        let (sx, rx) = async_channel::unbounded();

        GenericReadWriter {
            reader: BufReader::new(reader),
            notifier: None,
            sink: Box::new(transformer),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            current_file_context: None,
            external_receiver: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, transformer))]
    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(
        mut self,
        mut transformer: T,
    ) -> Self {
        self.transformers.push(Box::new(transformer));
        self
    }

    #[tracing::instrument(level = "trace", skip(self, file_ctx))]
    pub fn set_file_ctx(&mut self, file_ctx: FileContext) {
        self.current_file_context = Some((file_ctx, false));
    }
}

#[async_trait::async_trait]
impl<'a, R: AsyncRead + Unpin + Send + Sync> ReadWriter for GenericReadWriter<'a, R> {
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
    async fn announce_all(&mut self, message: Message) -> Result<()> {
        if let Some(notifier) = &self.notifier {
            notifier.send_all(message)?;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, rx))]
    async fn add_message_receiver(&mut self, rx: Receiver<Message>) -> Result<()> {
        if self.external_receiver.is_none() {
            self.external_receiver = Some(rx);
            Ok(())
        } else {
            error!("Overwriting existing receivers is not allowed!");
            bail!("[READ_WRITER] Overwriting existing receivers is not allowed!")
        }
    }
}
