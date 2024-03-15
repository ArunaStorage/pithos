use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pithos_lib::{
    readwrite::GenericReadWriter,
    transformer::ReadWriter,
    transformers::{
        decrypt::ChaCha20Dec, encrypt::ChaCha20Enc, zstd_comp::ZstdEnc, zstd_decomp::ZstdDec,
    },
};
use tokio::fs::File;

#[tracing::instrument(level = "trace", skip())]
async fn read_writer_with_file() {
    let file = File::open("test.txt").await.unwrap();
    let file2 = File::create("test.txt.out.1").await.unwrap();

    // Create a new GenericReadWriter
    GenericReadWriter::new_with_writer(file, file2)
        .add_transformer(ZstdEnc::new())
        .add_transformer(ZstdEnc::new())
        .add_transformer(
            ChaCha20Enc::new_with_fixed(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .add_transformer(
            ChaCha20Enc::new_with_fixed(
                b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .add_transformer(
            ChaCha20Dec::new_with_fixed(
                b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .add_transformer(
            ChaCha20Dec::new_with_fixed(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .add_transformer(ZstdDec::new())
        .add_transformer(ZstdDec::new())
        .process()
        .await
        .unwrap();
}

#[tracing::instrument(level = "trace", skip())]
async fn read_writer_with_vec() {
    let file = b"This is a very very important test".to_vec();
    let mut file2 = Vec::new();

    // Create a new GenericReadWriter
    GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
        .add_transformer(ZstdEnc::new())
        .add_transformer(ZstdEnc::new())
        .add_transformer(
            ChaCha20Enc::new_with_fixed(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .add_transformer(
            ChaCha20Enc::new_with_fixed(
                b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .add_transformer(
            ChaCha20Dec::new_with_fixed(
                b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .add_transformer(
            ChaCha20Dec::new_with_fixed(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .add_transformer(ZstdDec::new())
        .add_transformer(ZstdDec::new())
        .process()
        .await
        .unwrap();
}

#[tracing::instrument(level = "trace", skip(c))]
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_benches");
    group.measurement_time(Duration::from_secs(10));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    group.bench_function(BenchmarkId::new("read_writer_with_file", "10s"), |b| {
        b.to_async(&runtime).iter(read_writer_with_file);
    });

    group.bench_function(BenchmarkId::new("read_writer_with_vec", "10s"), |b| {
        b.to_async(&runtime).iter(read_writer_with_vec);
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
