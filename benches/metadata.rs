use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

const DB_FILE: &str = "GeoLite2-City.mmdb";

pub fn metadata_benchmark(c: &mut Criterion) {
    let reader = maxminddb::Reader::open_readfile(DB_FILE).unwrap();

    c.bench_function("metadata/build_time", |b| {
        b.iter(|| black_box(reader.metadata().build_time().unwrap()))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = metadata_benchmark
}
criterion_main!(benches);
