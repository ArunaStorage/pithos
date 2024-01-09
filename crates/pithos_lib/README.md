[![Rust](https://img.shields.io/badge/built_with-Rust-dca282.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/ArunaStorage/aruna-file/blob/main/LICENSE)
![CI](https://github.com/ArunaStorage/aruna-file/actions/workflows/push.yaml/badge.svg)
[![Codecov](https://codecov.io/github/ArunaStorage/aruna-file/coverage.svg?branch=main)](https://codecov.io/gh/ArunaStorage/aruna-file)
[![Dependency status](https://deps.rs/repo/github/ArunaStorage/aruna-file/status.svg)](https://deps.rs/repo/github/ArunaStorage/aruna-file)
___

# Pithos library

A library for creating handling and transforming Pithos files, an object storage optimised file format for Research Data Management (RDM).

# Description

The library contains a custom Read/Write component that allows for dynamic transformation data in multiple input and output formats.
While initially focused on usage as backend format in the ArunaObjectStorage the scope has significantly widened, this now support transformation 
from / to Pithos files for a wide variety of options including:

- Encryption (ChaCha20-Poly1305)
- Compression (Zstandard)
- Indexing
- Metadata handling
- Bundling of multiple .pto into .tar.gz archives

## Guidance 

Short guidance for usage of the `PithosReadWriter` and similarly for the `PithosStreamReadWriter` custom component. For the formal file specification click [here](../../spec/SPECIFICATION.md).

An overhauled generic version of customisable data transformer component for the Pithos file format and associated transformation logic.
The idea is simple, you implement these simple base trait with your custom data transformation logic:

```rust
#[async_trait::async_trait]
pub trait Transformer {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool>;
}
```

And afterwards the structs implementing `Transformer` can be registered in the `PithosReadWriter` to be plugged between the `Read` and `Write` parts of a ReadWriter.

Example:

```rust
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new PithosReadWriter
        PithosReadWriter::new_with_writer(file.as_ref(), &mut file2)
            .add_transformer(ZstdEnc::new(1, false))
            .add_transformer(ZstdEnc::new(2, false)) // Double compression because we can
            .add_transformer(
                ChaCha20Enc::new(false, b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new(false, b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new(Some(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec())).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new(Some(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec())).unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new())
            .add_transformer(Filter::new(Range { from: 0, to: 3 }))
            .process()
            .await
            .unwrap();
        assert_eq!(file2, b"Thi".to_vec());
```

This example creates a `Vec<u8>` from a bytes array (implements [AsyncRead](https://docs.rs/tokio/1.26.0/tokio/io/trait.AsyncRead.html)) and sinks it in another `Vec<u8>` (impl [AsynWrite](https://docs.rs/tokio/1.26.0/tokio/io/trait.AsyncWrite.html)). In between, custom data transformations can take place.

The example compresses the vector two times with a custom padded Zstandard compression component and afterwards encrypts the result also two times with ChaCha20-Poly1305. Afterwards all steps are reversed resulting in the original data.

### Notes for own implementations

The main logic is build around, the process_bytes function.

```rust
async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool, should_flush: bool) -> Result<bool>;
```

The idea is that your Transformer receives a mutable buffer with bytes that you MUST transform. If you have transformed (either all or via an internal buffer) the data is put back into the buffer for the next transformers `process_bytes` method. If `should_flush` is `true` all internal buffers should be flushed and cleared immediately.