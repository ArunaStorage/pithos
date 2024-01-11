use async_channel::{Receiver, Sender};
use bytes::Bytes;
use futures::Stream;

use crate::{
    notifications::Message,
    transformer::{FileContext, Sink, Transformer, TransformerType},
};

pub struct PithosReader<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
        + Unpin
        + Send
        + Sync,
> {
    input_stream: R,
    transformers: Vec<(TransformerType, Box<dyn Transformer + Send + Sync + 'a>)>,
    sink: Box<dyn Sink + Send + Sync + 'a>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    size_counter: usize,
    current_file_context: Option<(FileContext, bool)>,
    file_ctx_rx: Option<Receiver<(FileContext, bool)>>,
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > PithosReader<'a, R>
{
    #[tracing::instrument(level = "trace", skip(input_stream, sink))]
    pub fn new<T: Transformer + Sink + Send + Sync + 'a>(
        input_stream: R,
        sink: T,
        filecontext: FileContext,
        metadata: Option<String>,
    ) -> Self {
        todo!()
    }
}
