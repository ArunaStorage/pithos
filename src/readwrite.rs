use std::io::Cursor;

use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdEncoder;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
};

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
        let mut read_buf = BytesMut::with_capacity(RAW_CHUNK_SIZE + 65_536);
        let mut raw_block_size = 0;
        let mut comp_size = 0;
        let mut consumed = 0;

        let mut compressor = if self.encrypting {
            Some(ZstdEncoder::new(Vec::with_capacity(
                RAW_CHUNK_SIZE + 65_536,
            )))
        } else {
            None
        };

        let mut encrypter: Vec<u8> = Vec::new();

        let mut last = BytesMut::with_capacity(65_536);

        loop {
            // raw_block_size += self.reader.read_buf(&mut read_buf).await?;

            // if raw_block_size > RAW_CHUNK_SIZE {
            //     last = read_buf.split_to(raw_block_size % RAW_CHUNK_SIZE);
            //     compressor.write_buf(&mut last).await?;
            //     compressor.flush().await?;
            //     compressor = ZstdEncoder::new(Vec::with_capacity(RAW_CHUNK_SIZE + 32_768));
            //     raw_block_size = read_buf.len();
            // }

            // compressor.flush().await?;
            // let internal_len = compressor.get_ref().len();
            // if internal_len - consumed > 10 {
            //     let get_data = &compressor.get_ref()[consumed..internal_len];
            //     consumed += get_data.len();
            //     encrypter.extend(get_data);
            //     println!("{:?}", hex::encode(encrypter.clone()));
            // }

            // compressor.write_buf(&mut read_buf.split()).await?;

            // if bytes_read == 0 {
            //     compressor.flush().await?;
            //     compressor.shutdown().await?;
            //     break;
            // }
        }

        Ok(())
    }

    async fn compress(&self) -> Result<()> {
        Ok(())
    }
}
