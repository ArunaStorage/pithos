use crate::helpers::notifications::Message;
use crate::helpers::structs::FileContext;
use crate::streamreadwrite::GenericStreamReadWriter;
use crate::transformer::{ReadWriter, Sink, Transformer};
use crate::transformers::encrypt::ChaCha20Enc;
use crate::transformers::footer::FooterGenerator;
use crate::transformers::hashing_transformer::HashingTransformer;
use crate::transformers::zstd_comp::ZstdEnc;
use anyhow::Result;
use bytes::Bytes;
use digest::Digest;
use futures::Stream;
use md5::Md5;
use sha1::Sha1;
use tokio::io::AsyncWrite;
use crate::transformers::pithos_comp_enc::PithosTransformer;

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
        file_contexts: Vec<FileContext>,
        metadata: Option<String>,
    ) -> Result<Self> {
        let mut stream_read_writer = GenericStreamReadWriter::new_with_writer(input_stream, writer)
            .add_transformer(HashingTransformer::new(Md5::new(), "md5".to_string()))
            .add_transformer(HashingTransformer::new(Sha1::new(), "sha1".to_string()))
            .add_transformer(ZstdEnc::new())
            .add_transformer(ChaCha20Enc::new())
            .add_transformer(FooterGenerator::new());

        // Send all FileContext into GenericStreamReadWriter message queue
        let (sender, receiver) = async_channel::unbounded();
        for file_context in file_contexts {
            sender
                .send(Message::FileContext(file_context.clone()))
                .await?;
        }

        stream_read_writer.add_message_receiver(receiver).await?;

        // Return default PithosWriter
        Ok(PithosWriter { stream_read_writer })
    }

    #[tracing::instrument(level = "trace", skip(input_stream, writer))]
    pub async fn new_multi_with_writer<W: AsyncWrite + Send + Sync + 'a>(
        input_stream: R,
        writer: W,
        file_contexts: Vec<FileContext>,
    ) -> Result<Self> {
        let mut stream_read_writer = GenericStreamReadWriter::new_with_writer(input_stream, writer)
            .add_transformer(HashingTransformer::new(Md5::new(), "md5".to_string()))
            .add_transformer(HashingTransformer::new(Sha1::new(), "sha1".to_string()))
            .add_transformer(PithosTransformer::new())
            .add_transformer(FooterGenerator::new());

        let (sender, receiver) = async_channel::bounded(10);
        for context in file_contexts {
            sender.send(Message::FileContext(context)).await?;
        }

        stream_read_writer.add_message_receiver(receiver).await?;

        // Return default multifile PithosWriter
        Ok(PithosWriter { stream_read_writer })
    }

    pub async fn process_bytes(&mut self) -> Result<()> {
        self.stream_read_writer.process().await
    }
}
