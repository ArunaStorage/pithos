mod crypt4gh;
pub mod helpers;
pub mod pithos;
pub mod readwrite;
pub mod streamreadwrite;
pub mod transformer;
pub mod transformers;

#[cfg(test)]
mod tests {
    //use crate::helpers::footer_parser::{FooterParser, Range};
    use crate::helpers::notifications::Message;
    use crate::helpers::structs::{EncryptionKey, FileContext, Range};
    use crate::readwrite::GenericReadWriter;
    use crate::streamreadwrite::GenericStreamReadWriter;
    use crate::transformer::ReadWriter;
    use crate::transformers::decrypt::ChaCha20Dec;
    use crate::transformers::encrypt::ChaCha20Enc;
    use crate::transformers::filter::Filter;
    use crate::transformers::footer::FooterGenerator;
    use crate::transformers::gzip_comp::GzipEnc;
    use crate::transformers::size_probe::SizeProbe;
    use crate::transformers::tar::TarEnc;
    use crate::transformers::zstd_comp::ZstdEnc;
    use crate::transformers::zstd_decomp::ZstdDec;
    use bytes::Bytes;
    use digest::Digest;
    use futures::{StreamExt, TryStreamExt};
    use md5::Md5;
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    #[tokio::test]
    async fn e2e_compressor_test_with_file() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.1").await.unwrap();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file, file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt.out.1").await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf1 == buf2)
    }

    #[tokio::test]
    async fn e2e_encrypt_test_with_vec_no_pad() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .process()
            .await
            .unwrap();

        assert_eq!(file, file2);
    }

    #[tokio::test]
    async fn e2e_encrypt_test_with_file_no_pad() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.2").await.unwrap();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file, file2)
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .process()
            .await
            .unwrap();

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt.out.2").await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf1 == buf2)
    }

    #[tokio::test]
    async fn e2e_test_roundtrip_with_file() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.4").await.unwrap();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file, file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt.out.4").await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf1 == buf2)
    }

    #[tokio::test]
    async fn test_with_vec() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdEnc::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new()) // Double decompression because we can
            .process()
            .await
            .unwrap();
        assert!(file == file2)
    }

   /* #[tokio::test]
    async fn test_with_file_footer_ctx() {
        let file = File::open("test.txt").await.unwrap();
        let size = file.metadata().await.unwrap().len();
        let file2 = File::create("test.txt.out.5").await.unwrap();
        let mut read_writer = GenericReadWriter::new_with_writer(file, file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ChaCha20Enc::new())
            .add_transformer(FooterGenerator::new(None));

        read_writer
            .set_file_ctx(FileContext {
                file_path: "test.txt".to_string(),
                compressed_size: size,
                decompressed_size: 0,
                encryption_key: EncryptionKey::Same(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()),
                ..Default::default()
            })
            .await;

        read_writer.process().await.unwrap();

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt.out.5").await.unwrap();
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        file.read_to_end(&mut buf1).await.unwrap();
        file2.read_to_end(&mut buf2).await.unwrap();
        assert_eq!(buf1 == buf2)
    }*/

    #[tokio::test]
    async fn test_footer_parsing() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.6").await.unwrap();
        GenericReadWriter::new_with_writer(file, file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                FooterGenerator::new_with_ctx(FileContext {
                    file_path: "test.txt".to_string(),
                    ..Default::default()
                })
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        let mut file2 = File::open("test.txt.out.6").await.unwrap();
        file2
            .seek(std::io::SeekFrom::End(-65536 * 2))
            .await
            .unwrap();

        let buf: &mut [u8; 65536 * 2] = &mut [0; 65536 * 2];
        file2.read_exact(buf).await.unwrap();

        //let mut fp = FooterParser::new(buf);

        //fp.parse().unwrap();

        // let (a, b) = fp
        //     .get_offsets_by_range(Range { from: 0, to: 1000 })
        //     .unwrap();

        // assert!(a.to % (65536) == 0);

        // assert_eq!(
        //     a,
        //     Range {
        //         from: 0,
        //         to: 25 * 65536
        //     }
        // );
        // assert!(b == Range { from: 0, to: 1000 })
    }

    #[tokio::test]
    async fn test_footer_parsing_encrypted() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.7").await.unwrap();
        GenericReadWriter::new_with_writer(file, file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                FooterGenerator::new_with_ctx(FileContext {
                    file_path: "test.txt".to_string(),
                    encryption_key: EncryptionKey::Same(
                        b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec(),
                    ),
                    ..Default::default()
                })
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        let mut file2 = File::open("test.txt.out.7").await.unwrap();
        file2
            .seek(std::io::SeekFrom::End((-65536 - 28) * 2))
            .await
            .unwrap();

        let buf: &mut [u8; (65536 + 28) * 2] = &mut [0; (65536 + 28) * 2];
        file2.read_exact(buf).await.unwrap();

        // let mut fp = FooterParser::new(buf);
        // fp.parse().unwrap();

        // let (a, b) = fp
        //     .get_offsets_by_range(Range { from: 0, to: 1000 })
        //     .unwrap();

        // assert!(a.to % (65536 + 28) == 0);

        // assert!(
        //     a == Range {
        //         from: 0,
        //         to: 25 * (65536 + 28)
        //     }
        // );
        // assert!(b == Range { from: 0, to: 1000 })
    }

    #[tokio::test]
    async fn test_with_filter() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdEnc::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new())
            .add_transformer(Filter::new_with_range(Range { from: 0, to: 3 }))
            .process()
            .await
            .unwrap();

        println!("{:?}", file2);
        assert_eq!(file2, b"Thi".to_vec());
    }

    #[tokio::test]
    async fn test_read_write_multifile() {
        let file1 = b"This is a very very important test".to_vec();
        let file2 = b"This is a very very important test".to_vec();
        let mut file3: Vec<u8> = Vec::new();

        let combined = Vec::from_iter(file1.clone().into_iter().chain(file2.clone()));

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1.len() as u64,
            decompressed_size: file1.len() as u64,
            compression: true,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2.len() as u64,
            decompressed_size: file2.len() as u64,
            compression: false,
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericReadWriter
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut file3);
        aswr.add_message_receiver(rx).await.unwrap();
        aswr = aswr
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdEnc::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new())
            .add_transformer(Filter::new_with_range(Range { from: 0, to: 3 }));
        aswr.process().await.unwrap();
        drop(aswr);

        println!("{:?}", file3);
        assert_eq!(file3, b"Thi".to_vec());
    }

    #[tokio::test]
    async fn stream_test() {
        let mut file2 = Vec::new();

        use futures::stream;

        let stream = stream::iter(vec![
            Ok(Bytes::from_iter(
                b"This is a very very important test".to_vec(),
            )),
            Ok(Bytes::from(b"This is a very very important test".to_vec())),
        ]);

        // Create a new GenericStreamReadWriter
        GenericStreamReadWriter::new_with_writer(stream, &mut file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdEnc::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new())
            .add_transformer(Filter::new_with_range(Range { from: 0, to: 3 }))
            .process()
            .await
            .unwrap();

        dbg!(format!("{:?}", std::str::from_utf8(&file2)));
        assert_eq!(file2, b"Thi".to_vec());
    }

    #[tokio::test]
    async fn e2e_test_read_write_multifile_tar_small() {
        let file1 = b"This is a very very important test".to_vec();
        let file2 = b"Another brilliant This is a very very important test1337".to_vec();
        let mut file3 = File::create("test.txt.out.8").await.unwrap();

        let combined = Vec::from_iter(file1.clone().into_iter().chain(file2.clone()));

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1.len() as u64,
            decompressed_size: file1.len() as u64,
            compression: true,
            encryption_key: EncryptionKey::Same(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()),
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2.len() as u64,
            decompressed_size: file2.len() as u64,
            compression: false,
            encryption_key: EncryptionKey::Same(b"xxwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericReadWriter
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut file3)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_read_write_multifile_tar_real() {
        let mut file1 = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt").await.unwrap();
        let mut file3 = File::create("test.txt.out.9").await.unwrap();

        let mut combined = Vec::new();
        file1.read_to_end(&mut combined).await.unwrap();
        file2.read_to_end(&mut combined).await.unwrap();

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1.metadata().await.unwrap().len(),
            decompressed_size: file1.metadata().await.unwrap().len(),
            compression: true,
            encryption_key: EncryptionKey::Same(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()),
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2.metadata().await.unwrap().len(),
            decompressed_size: file2.metadata().await.unwrap().len(),
            compression: false,
            encryption_key: EncryptionKey::Same(b"xxwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericReadWriter
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut file3)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_stream_write_multifile_tar_real() {
        let file1 = File::open("test.txt").await.unwrap();
        let file2 = File::open("test.txt").await.unwrap();

        let file1_size = file1.metadata().await.unwrap().len();
        let file2_size = file2.metadata().await.unwrap().len();

        let stream1 = tokio_util::io::ReaderStream::new(file1);
        let stream2 = tokio_util::io::ReaderStream::new(file2);

        let chained = stream1.chain(stream2);
        let mapped = chained.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });
        let mut file3 = File::create("test.txt.out.10").await.unwrap();

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1_size,
            decompressed_size: file1_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2_size,
            decompressed_size: file2_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_stream_tar_gz() {
        let file1 = File::open("test.txt").await.unwrap();
        let file2 = File::open("test.txt").await.unwrap();

        let file1_size = file1.metadata().await.unwrap().len();
        let file2_size = file2.metadata().await.unwrap().len();

        let stream1 = tokio_util::io::ReaderStream::new(file1);
        let stream2 = tokio_util::io::ReaderStream::new(file2);

        let chained = stream1.chain(stream2);
        let mapped = chained.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });
        let mut file3 = File::create("test.txt.out.11").await.unwrap();

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1_size,
            decompressed_size: file1_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2_size,
            decompressed_size: file2_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(TarEnc::new())
            .add_transformer(GzipEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn hashing_transformer_test() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        let (probe, rx) = SizeProbe::new();
        let md5_trans = crate::transformers::hashing_transformer::HashingTransformer::new(
            Md5::new(),
            "md5".to_string(),
            false,
        );

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
            .add_transformer(md5_trans)
            .add_transformer(probe)
            .process()
            .await
            .unwrap();

        let size = rx.try_recv().unwrap();
        //let md5 = rx2.try_recv().unwrap();
        // Todo: Receive MD5

        assert_eq!(size, 34);
        //assert_eq!(md5, "4f276870b4b5f84c0b2bbfce30757176".to_string());
    }

    #[tokio::test]
    async fn e2e_test_stream_tar_folder() {
        let file1 = File::open("test.txt").await.unwrap();
        let file2 = File::open("test.txt").await.unwrap();

        let file1_size = file1.metadata().await.unwrap().len();
        let file2_size = file2.metadata().await.unwrap().len();

        let stream1 = tokio_util::io::ReaderStream::new(file1);
        let stream2 = tokio_util::io::ReaderStream::new(file2);

        let chained = stream1.chain(stream2);
        let mapped = chained.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });
        let mut file3 = File::create("test.txt.out.tar").await.unwrap();

        let (sx, rx) = async_channel::bounded(10);

        sx.send(Message::FileContext(FileContext {
            file_path: "blup/".to_string(),
            compressed_size: 0,
            decompressed_size: 0,
            is_dir: true,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "blup/file1.txt".to_string(),
            compressed_size: file1_size,
            decompressed_size: file1_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "blip/".to_string(),
            compressed_size: 0,
            decompressed_size: 0,
            is_dir: true,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "blip/file2.txt".to_string(),
            compressed_size: file2_size,
            decompressed_size: file2_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        //.add_transformer(GzipEnc::new());
        aswr.process().await.unwrap();
    }
}
