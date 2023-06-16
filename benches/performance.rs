use std::time::Duration;

use aruna_file::{
    readwrite::ArunaReadWriter,
    transformer::ReadWriter,
    transformers::{
        compressor::ZstdEnc, decompressor::ZstdDec, decrypt::ChaCha20Dec, encrypt::ChaCha20Enc,
    },
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::fs::File;

async fn read_writer_with_file() {
    let file = File::open("test.txt").await.unwrap();
    let file2 = File::create("test.txt.out.1").await.unwrap();

    // Create a new ArunaReadWriter
    ArunaReadWriter::new_with_writer(file, file2)
        .add_transformer(ZstdEnc::new(1, false))
        .add_transformer(ZstdEnc::new(2, false))
        .add_transformer(
            ChaCha20Enc::new(false, b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
        )
        .add_transformer(
            ChaCha20Enc::new(false, b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
        )
        .add_transformer(ChaCha20Dec::new(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap())
        .add_transformer(ChaCha20Dec::new(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap())
        .add_transformer(ZstdDec::new())
        .add_transformer(ZstdDec::new())
        .process()
        .await
        .unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let size: usize = 125;

    let mut group = c.benchmark_group("file_benches");
    group.measurement_time(Duration::from_secs(10));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    group.bench_with_input(
        BenchmarkId::new("read_writer_with_file", size),
        &size,
        |b, _| {
            // Insert a call to `to_async` to convert the bencher to async mode.
            // The timing loops are the same as with the normal bencher.
            b.to_async(&runtime).iter(|| read_writer_with_file());
        },
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
