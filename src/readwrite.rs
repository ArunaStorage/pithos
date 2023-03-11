use crate::transformer::Transformer;
use crate::{finalizer::Finalizer, transformer::AddTransformer};
use anyhow::Result;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};

pub struct ArunaReadWriter<'a, R: AsyncRead + Unpin> {
    reader: BufReader<R>,
    sink: Box<dyn Transformer + Send + 'a>,
}

impl<'a, R: AsyncRead + Unpin> ArunaReadWriter<'a, R> {
    pub fn new<W: AsyncWrite + Unpin + Send + 'a>(reader: R, writer: W) -> ArunaReadWriter<'a, R> {
        ArunaReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(Finalizer::new(BufWriter::new(writer))),
        }
    }

    pub fn add_transformer<T: Transformer + AddTransformer<'a> + Send + 'a>(
        mut self,
        mut t: T,
    ) -> ArunaReadWriter<'a, R> {
        t.add_transformer(self.sink);
        self.sink = Box::new(t);
        self
    }

    pub async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut bytes_read;
        let mut read_buf = BytesMut::with_capacity(65_536);

        loop {
            bytes_read = self.reader.read_buf(&mut read_buf).await?;
            if bytes_read != 0 {
                self.sink
                    .process_bytes(&mut read_buf.split().freeze(), false)
                    .await?;
            } else {
                if self
                    .sink
                    .process_bytes(&mut read_buf.split().freeze(), true)
                    .await?
                    == true
                {
                    break;
                }
            }
        }
        Ok(())
    }
}
