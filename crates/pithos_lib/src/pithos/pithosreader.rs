use anyhow::Result;
use bytes::Bytes;
use futures::Stream;
use tokio::io::AsyncWrite;

use crate::helpers::structs::FileContext;
use crate::streamreadwrite::GenericStreamReadWriter;
use crate::transformer::{ReadWriter, Sink, Transformer};
use crate::transformers::decrypt::ChaCha20Dec;
use crate::transformers::filter::Filter;
use crate::transformers::zstd_decomp::ZstdDec;

pub struct PithosReader<
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
    > PithosReader<'a, R>
{
    #[tracing::instrument(level = "trace", skip(_input_stream, _sink))]
    pub fn new<T: Transformer + Sink + Send + Sync + 'a>(
        _input_stream: R,
        _sink: T,
        filecontext: FileContext,
        metadata: Option<String>,
    ) -> Self {
        todo!()
    }

    #[tracing::instrument(level = "trace", skip(input_stream, writer))]
    pub async fn new_with_writer<W: AsyncWrite + Send + Sync + 'a>(
        input_stream: R,           // Only contains the data payload of the specific file
        writer: W,                 // Output target
        file_context: FileContext, // Parsed from footer and filtered by user input
        range_filter: Option<Vec<u64>>,
    ) -> Result<Self> {
        // Reverse PithosTransformer
        let mut stream_read_writer = GenericStreamReadWriter::new_with_writer(input_stream, writer);

        if let Some(key) = file_context.encryption_key.get_data_key() {
            stream_read_writer =
                stream_read_writer.add_transformer(ChaCha20Dec::new_with_fixed(key)?);
        }
        if file_context.compression {
            stream_read_writer = stream_read_writer.add_transformer(ZstdDec::new());
        }
        if let Some(edit_list) = range_filter {
            stream_read_writer =
                stream_read_writer.add_transformer(Filter::new_with_edit_list(Some(edit_list)));
        }

        Ok(PithosReader { stream_read_writer })
    }

    pub async fn process_bytes(&mut self) -> Result<()> {
        self.stream_read_writer.process().await
    }
}
