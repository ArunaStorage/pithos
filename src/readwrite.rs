use std::io::Cursor;

use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdEncoder;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
};

use crate::compressor::Compressor;
use crate::transformer::Transformer;

const RAW_CHUNK_SIZE: usize = 5_242_880;

pub struct ArunaReadWriter<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
    compressing: bool,
    encrypting: bool,
    encryption_key: bytes::Bytes,
    expected_size: u64,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> ArunaReadWriter<R, W> {
    pub async fn new(reader: R, writer: W) -> Self {
        ArunaReadWriter {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
            compressing: false,
            encrypting: false,
            encryption_key: Bytes::new(),
            expected_size: 0,
        }
    }

    pub async fn add_compressor(mut self) -> Self {
        self.compressing = true;
        self
    }

    pub async fn add_encryption(mut self, enc_key: bytes::Bytes) -> Self {
        self.encrypting = true;
        self.encryption_key = enc_key;
        self
    }

    pub async fn set_expected_size(mut self, expected_size: u64) -> Self {
        self.expected_size = expected_size;
        self
    }

    pub async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut bytes_read;
        let mut read_buf = BytesMut::with_capacity(65_536);
        let mut comp = Compressor::new(0).await;

        loop {
            bytes_read = self.reader.read_buf(&mut read_buf).await?;
            if bytes_read != 0 {
                comp.write_bytes(&mut read_buf.split().freeze()).await?;
            }

            loop {
                if let Some(chunk) = comp.get_chunk().await? {
                    self.writer.write(&chunk).await?;
                } else {
                    break;
                }
            }
            if bytes_read == 0 {
                comp.finish(false).await?;
                if let Some(chunk) = comp.get_chunk().await? {
                    dbg!(chunk.len());
                    self.writer.write(&chunk).await?;
                    continue;
                }
                break;
            }
        }
        self.writer.flush().await?;

        println!("{:?}", comp.get_chunk_list().await.1.len());

        Ok(())
    }
}
