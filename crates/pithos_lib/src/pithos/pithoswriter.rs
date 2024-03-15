use crate::helpers::notifications::Message;
use crate::helpers::structs::FileContext;
use crate::streamreadwrite::GenericStreamReadWriter;
use crate::transformer::{ReadWriter, Sink, Transformer};
use crate::transformers::footer::FooterGenerator;
use crate::transformers::hashing_transformer::HashingTransformer;
use crate::transformers::pithos_comp_enc::PithosTransformer;
use anyhow::Result;
use async_channel::Receiver;
use bytes::Bytes;
use digest::Digest;
use futures::Stream;
use md5::Md5;
use sha2::Sha256;
use tokio::io::AsyncWrite;

pub struct PithosWriter<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
        + Unpin
        + Send
        + Sync,
> {
    #[allow(dead_code)]
    stream_read_writer: GenericStreamReadWriter<'a, R>,
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > PithosWriter<'a, R>
{
    #[tracing::instrument(level = "trace", skip(_input_stream, _sink))]
    pub fn new_with_sink<T: Transformer + Sink + Send + Sync + 'a>(
        _input_stream: R,
        _sink: T,
        file_context: FileContext,
        metadata: Option<String>,
    ) -> Result<Self> {
        todo!();
    }

    #[tracing::instrument(level = "trace", skip(input_stream, writer))]
    pub async fn new_with_writer<W: AsyncWrite + Send + Sync + 'a>(
        input_stream: R,
        writer: W,
        file_context_receiver: Receiver<Message>,
        writer_private_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        let mut stream_read_writer = GenericStreamReadWriter::new_with_writer(input_stream, writer)
            .add_transformer(HashingTransformer::new(Md5::new(), "md5".to_string(), true))
            .add_transformer(HashingTransformer::new(
                Sha256::new(),
                "sha256".to_string(),
                true,
            ))
            .add_transformer(PithosTransformer::new())
            .add_transformer(FooterGenerator::new(writer_private_key));

        stream_read_writer
            .add_message_receiver(file_context_receiver)
            .await?;

        // Return default multifile PithosWriter
        Ok(PithosWriter { stream_read_writer })
    }

    pub async fn process_bytes(&mut self) -> Result<()> {
        self.stream_read_writer.process().await
    }
}
