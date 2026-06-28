use criterion::{criterion_group, criterion_main, Criterion};
use maxminddb::{geoip2, Reader};
use std::hint::black_box;

fn bench_networks_city_test(c: &mut Criterion) {
    let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();

    c.bench_function("within/networks_city_test", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for result in reader.networks(Default::default()).unwrap() {
                let lookup = result.unwrap();
                black_box(lookup.network().unwrap());
                count += 1;
            }
            black_box(count);
        });
    });
}

fn bench_within_city_subnet(c: &mut Criterion) {
    let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let cidr = "81.2.69.0/24".parse().unwrap();

    c.bench_function("within/city_subnet", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for result in reader.within(cidr, Default::default()).unwrap() {
                let lookup = result.unwrap();
                let city: Option<geoip2::City<'_>> = lookup.decode().unwrap();
                black_box(city);
                count += 1;
            }
            black_box(count);
        });
    });
}

fn bench_networks_mixed_test(c: &mut Criterion) {
    let reader =
        Reader::open_readfile("test-data/test-data/MaxMind-DB-test-mixed-24.mmdb").unwrap();

    c.bench_function("within/networks_mixed_test", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for result in reader.networks(Default::default()).unwrap() {
                let lookup = result.unwrap();
                black_box(lookup.network().unwrap());
                count += 1;
            }
            black_box(count);
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_networks_city_test, bench_within_city_subnet, bench_networks_mixed_test
}
criterion_main!(benches);
