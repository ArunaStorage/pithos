use crate::notifications::{Message, Notifier};
use crate::structs::FileContext;
use crate::transformer::{ReadWriter, Sink, Transformer};
use crate::transformers::writer_sink::WriterSink;
use anyhow::{anyhow, bail, Result};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::BytesMut;
use std::mem;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};
use tracing::error;

pub struct GenericReadWriter<'a, R: AsyncRead + Unpin> {
    reader: BufReader<R>,
    notifier: Option<Arc<Notifier>>,
    transformers: Vec<Box<dyn Transformer + Send + Sync + 'a>>,
    sink: Option<Box<dyn Transformer + Send + Sync + 'a>>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    size_counter: usize,
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
            sink: Some(Box::new(WriterSink::new(BufWriter::new(writer)))),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            external_receiver: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(reader, sink))]
    pub fn new_with_sink<T: Transformer + Sink + Send + Sync + 'a>(
        reader: R,
        sink: T,
    ) -> GenericReadWriter<'a, R> {
        let (sx, rx) = async_channel::bounded(10);

        GenericReadWriter {
            reader: BufReader::new(reader),
            notifier: None,
            sink: Some(Box::new(sink)),
            transformers: Vec::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            external_receiver: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, transformer))]
    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(mut self, transformer: T) -> Self {
        self.transformers.push(Box::new(transformer));
        self
    }

    #[tracing::instrument(level = "trace", skip(self, file_ctx))]
    pub async fn set_file_ctx(&mut self, file_ctx: FileContext) -> Result<()> {
        Ok(self.sender.send(Message::FileContext(file_ctx)).await?)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn process_messages(
        &self,
        file_ctx: &mut Option<FileContext>,
        next_ctx: &mut Option<FileContext>,
    ) -> Result<bool> {
        loop {
            match self.receiver.try_recv() {
                Err(TryRecvError::Empty) => break,
                Ok(ref msg) => match msg {
                    Message::FileContext(context) => {
                        if file_ctx.is_some() {
                            if let None = next_ctx {
                                *next_ctx = Some(context.clone());
                            } else {
                                bail!("File contexts already set!")
                            }
                        } else {
                            *file_ctx = Some(context.clone());
                        }
                    }
                    Message::Completed => {
                        return Ok(true);
                    }
                    _ => {}
                },
                Err(TryRecvError::Closed) => bail!("Channel closed!"),
            }
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl<'a, R: AsyncRead + Unpin + Send + Sync> ReadWriter for GenericReadWriter<'a, R> {
    #[tracing::instrument(err, level = "trace", skip(self))]
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut read_buf = BytesMut::with_capacity(65_536 * 2);
        let mut hold_buffer = BytesMut::with_capacity(65536);
        let mut read_bytes: usize = 0;
        let mut next_file_ctx: Option<FileContext> = None;
        let mut file_ctx: Option<FileContext> = None;
        self.transformers
            .push(self.sink.take().ok_or_else(|| anyhow!("No sink!"))?);

        let notifier = Arc::new(Notifier::new(self.sender.clone()));
        for (idx, t) in self.transformers.iter_mut().enumerate() {
            notifier.add_transformer(t.initialize(idx).await);
            t.set_notifier(notifier.clone()).await?;
        }

        let _ = self.process_messages(&mut file_ctx, &mut next_file_ctx)?;

        if let Some(ctx) = &file_ctx {
            notifier.send_all(Message::FileContext(ctx.clone()))?;
        }

        loop {
            if hold_buffer.is_empty() {
                read_bytes = self.reader.read_buf(&mut read_buf).await?;
            } else if read_buf.is_empty() {
                mem::swap(&mut hold_buffer, &mut read_buf);
                if let Some(ctx) = &file_ctx {
                    notifier.send_all(Message::FileContext(ctx.clone()))?;
                }
            }

            if file_ctx.is_none() && read_buf.is_empty() && hold_buffer.is_empty() {
                notifier.send_first(Message::Finished)?;
            }

            let completed = self.process_messages(&mut file_ctx, &mut next_file_ctx)?;

            if let Some(context) = &file_ctx {
                self.size_counter += read_bytes;
                if self.size_counter > context.input_size as usize {
                    let mut diff = read_bytes - (self.size_counter - context.input_size as usize);
                    if diff >= context.input_size as usize {
                        diff = context.input_size as usize
                    }
                    hold_buffer = read_buf.split_to(diff);
                    mem::swap(&mut read_buf, &mut hold_buffer);
                    self.size_counter -= context.input_size as usize;
                    file_ctx = next_file_ctx;
                    next_file_ctx = None;
                } else if self.size_counter == context.input_size as usize && hold_buffer.is_empty()
                {
                    file_ctx = next_file_ctx;
                    next_file_ctx = None;
                }
            }

            for t in self.transformers.iter_mut() {
                t.process_bytes(&mut read_buf).await?;
            }

            if read_buf.is_empty() && completed {
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
