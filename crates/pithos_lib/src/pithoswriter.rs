use crate::streamreadwrite::GenericStreamReadWriter;
use crate::structs::FileContext;
use crate::transformer::{Sink, Transformer};
use anyhow::Result;
use bytes::Bytes;
use futures::Stream;

pub struct PithosWriter<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
        + Unpin
        + Send
        + Sync,
> {
    _stream_read_writer: GenericStreamReadWriter<'a, R>,
    _file_context: FileContext,
    _metadata: Option<String>, // Validated JSON
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
    pub fn new<T: Transformer + Sink + Send + Sync + 'a>(
        _input_stream: R,
        _sink: T,
        file_context: FileContext,
        metadata: Option<String>,
    ) -> Result<Self> {
        todo!();
        // let mut stream_read_writer = GenericStreamReadWriter::new_with_sink(input_stream, sink);

        // // Hashes
        // let (md5_transformer, md5_receiver) = HashingTransformer::new(Md5::new());
        // let (sha1_transformer, sha1_receiver) = HashingTransformer::new(Sha1::new());
        // stream_read_writer = stream_read_writer.add_transformer(md5_transformer);
        // stream_read_writer = stream_read_writer.add_transformer(sha1_transformer);

        // if file_context.compression {
        //     stream_read_writer = stream_read_writer.add_transformer(ZstdEnc::new(false));
        // }
        // if let Some(encryption_key) = &file_context.encryption_key {
        //     stream_read_writer = stream_read_writer
        //         .add_transformer(ChaCha20Enc::new(false, encryption_key.clone())?);
        // }
        // stream_read_writer = stream_read_writer.add_transformer(FooterGenerator::new(None));

        // Ok(PithosWriter {
        //     stream_read_writer,
        //     file_context,
        //     metadata,
        // })
    }
}
