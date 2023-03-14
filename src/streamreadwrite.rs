use crate::transformer::AddTransformer;
use crate::transformer::{Sink, Transformer};
use anyhow::anyhow;
use anyhow::Result;
use bytes::Bytes;
use futures::{Stream, StreamExt};

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
        }
        Ok(())
    }
}
