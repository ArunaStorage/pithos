use anyhow::Result;
use async_channel::{Receiver, Sender};
use bytes::Bytes;
use futures::Stream;
use tokio::io::AsyncWrite;

use crate::helpers::notifications::Message;
use crate::helpers::structs::FileContext;
use crate::transformer::{Sink, Transformer, TransformerType};

pub struct PithosReader<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
        + Unpin
        + Send
        + Sync,
> {
    _input_stream: R,
    _transformers: Vec<(TransformerType, Box<dyn Transformer + Send + Sync + 'a>)>,
    _sink: Box<dyn Sink + Send + Sync + 'a>,
    _receiver: Receiver<Message>,
    _sender: Sender<Message>,
    _size_counter: usize,
    _current_file_context: Option<(FileContext, bool)>,
    _file_ctx_rx: Option<Receiver<(FileContext, bool)>>,
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

    #[tracing::instrument(level = "trace", skip(_input_stream, _writer))]
    pub async fn new_with_writer<W: AsyncWrite + Send + Sync + 'a>(
        _input_stream: R,
        _writer: W,
        file_context: FileContext,
        metadata: Option<String>,
    ) -> Result<Self> {
        todo!();
    }
}
