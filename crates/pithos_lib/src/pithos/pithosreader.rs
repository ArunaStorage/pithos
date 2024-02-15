use anyhow::Result;
use bytes::Bytes;
use futures::Stream;
use tokio::io::AsyncWrite;

use crate::helpers::notifications::Message;
use crate::helpers::structs::FileContext;
use crate::streamreadwrite::GenericStreamReadWriter;
use crate::transformer::{ReadWriter, Sink, Transformer};

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
        input_stream: R, // Only contains the data payload of the specific files
        writer: W,       // Output target
        file_contexts: Vec<FileContext>, // Parsed from footer and filtered by user input
    ) -> Result<Self> {
        // Reverse PithosTransformer somehow
        let mut stream_read_writer = GenericStreamReadWriter::new_with_writer(input_stream, writer);
        unimplemented!("Reverse PithosTransformer");

        //TODO: As long as this is not async moved the max number of files is limited to the size of the channel
        let (sender, receiver) = async_channel::bounded(10);
        for context in file_contexts {
            sender.send(Message::FileContext(context)).await?;
        }
        stream_read_writer.add_message_receiver(receiver).await?;

        Ok(PithosReader { stream_read_writer })
    }
}
