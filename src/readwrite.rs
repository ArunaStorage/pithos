use std::io::Cursor;

use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdEncoder;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
};

use crate::compressor::Compressor;
use crate::finalizer::Finalizer;
use crate::transformer::Transformer;

const RAW_CHUNK_SIZE: usize = 5_242_880;

pub struct ArunaReadWriter<'a, R: AsyncRead + Unpin + 'a> {
    reader: BufReader<R>,
    sink: Box<dyn Transformer + Send + 'a>,
    encryption_key: bytes::Bytes,
    expected_size: u64,
}

impl<'a, R: AsyncRead + Unpin + 'a> ArunaReadWriter<'a, R> {
    pub async fn new<W: AsyncWrite + Unpin + Send + 'a>(
        reader: R,
        writer: W,
    ) -> ArunaReadWriter<'a, R> {
        ArunaReadWriter {
            reader: BufReader::new(reader),
            sink: Box::new(Finalizer::new(BufWriter::new(writer)).await),
            encryption_key: Bytes::new(),
            expected_size: 0,
        }
    }

    pub async fn add_compressor(mut self) -> ArunaReadWriter<'a, R> {
        let old = self.sink;
        self.sink = Box::new(Compressor::new(0, false, Some(old)).await);
        self
    }

    pub async fn _add_encryption(mut self, enc_key: bytes::Bytes) -> ArunaReadWriter<'a, R> {
        self.encryption_key = enc_key;
        self
    }

    pub async fn _set_expected_size(mut self, expected_size: u64) -> ArunaReadWriter<'a, R> {
        self.expected_size = expected_size;
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
