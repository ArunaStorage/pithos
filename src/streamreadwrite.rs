use crate::transformer::{AddTransformer, Notifications};
use crate::transformer::{Sink, Transformer};
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
        }
    }

    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + 'a>(
        input_stream: R,
        writer: W,
    ) -> ArunaStreamReadWriter<'a, R> {
        ArunaStreamReadWriter {
            input_stream,
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
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
            match self.input_stream.next().await {
                Some(b) => {
                    data = b.map_err(|_| anyhow!("Received error in stream"))?;
                }
                None => (),
            };
            bytes_read = data.len();
            if bytes_read != 0 {
                self.sink.process_bytes(&mut data, false).await?;
            } else {
                if self.sink.process_bytes(&mut data, true).await? == true {
                    break;
                }
            }

            log::debug!("StreamReadWriter: Processed {}", bytes_read);
        }
        Ok(())
    }

    pub async fn query_notifications(&mut self) -> Result<Vec<Notifications>> {
        let mut notes = Vec::new();
        self.sink.notify(&mut notes).await?;
        Ok(notes)
    }
}
