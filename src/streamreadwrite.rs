use crate::notifications::Notifications;
use crate::transformer::{Sink, Transformer, AddTransformer};
use crate::transformers::writer_sink::WriterSink;
use anyhow::anyhow;
use anyhow::Result;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use tokio::io::{AsyncWrite, BufWriter};

pub struct ArunaStreamReadWriter<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>> + Unpin,
> {
    input_stream: R,
    sink: Box<dyn Transformer + Send + 'a>,
    notes: Vec<Notifications>,
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>> + Unpin,
    > ArunaStreamReadWriter<'a, R>
{
    pub fn new_with_sink<T: Transformer + AddTransformer<'a> + Sink + Send + 'a>(
        input_stream: R,
        transformer: T,
    ) -> ArunaStreamReadWriter<'a, R> {
        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(transformer),
            notes: Vec::new(),
        }
    }

    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + 'a>(
        input_stream: R,
        writer: W,
    ) -> ArunaStreamReadWriter<'a, R> {
        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            notes: Vec::new()
        }
    }

    pub fn add_transformer<T: Transformer + AddTransformer<'a> + Send + 'a>(
        mut self,
        mut t: T,
    ) -> ArunaStreamReadWriter<'a, R> {
        t.add_transformer(self.sink);
        self.sink = Box::new(t);
        self
    }

    pub async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut bytes_read;
        let mut data = Bytes::new();

        loop {
            if let Some(b) = self.input_stream.next().await {
                data = b.map_err(|_| anyhow!("Received error in stream"))?;
            };
            bytes_read = data.len();
            if bytes_read != 0 {
                self.sink.process_bytes(&mut data, false).await?;
            } else if self.sink.process_bytes(&mut data, true).await? {
                break;
            }

            log::debug!("StreamReadWriter: Processed {}", bytes_read);
        }
        Ok(())
    }

    pub async fn get_notifications(&mut self) -> Result<Vec<Notifications>> {
        self.sink.notify(&mut self.notes).await?;
        Ok(self.notes.clone())
    }


    pub async fn notify(&mut self, note: Notifications) -> Result<()> {
        self.notes.push(note);
        self.sink.notify(&mut self.notes).await?;
        Ok(())
    }
}
