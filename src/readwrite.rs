use crate::transformer::{Notifications, Sink, Transformer};
use crate::{transformer::AddTransformer, transformers::writer_sink::WriterSink};
use anyhow::Result;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};

pub struct ArunaReadWriter<'a, R: AsyncRead + Unpin> {
    reader: BufReader<R>,
    sink: Box<dyn Transformer + Send + 'a>,
    notes: Vec<Notifications>,
}

impl<'a, R: AsyncRead + Unpin> ArunaReadWriter<'a, R> {
    pub fn new_with_writer<W: AsyncWrite + Unpin + Send + 'a>(
        reader: R,
        writer: W,
    ) -> ArunaReadWriter<'a, R> {
        ArunaReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(WriterSink::new(BufWriter::new(writer))),
            notes: Vec::new(),
        }
    }

    pub fn new_with_sink<T: Transformer + AddTransformer<'a> + Sink + Send + 'a>(
        reader: R,
        transformer: T,
    ) -> ArunaReadWriter<'a, R> {
        ArunaReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(transformer),
            notes: Vec::new()
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
            } else if self
                .sink
                .process_bytes(&mut read_buf.split().freeze(), true)
                .await?
            {
                break;
            }
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
