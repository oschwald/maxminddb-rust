#[macro_use]
extern crate criterion;
extern crate maxminddb;
extern crate rayon;

use criterion::Criterion;
use maxminddb::geoip2;
use rayon::prelude::*;

use std::net::{IpAddr, Ipv4Addr};

// Generate `count` IPv4 addresses from a deterministic LCG stream.
#[must_use]
pub fn generate_ipv4(count: u64) -> Vec<IpAddr> {
    let mut ips = Vec::with_capacity(count as usize);
    let mut state = 0x4D59_5DF4_D0F3_3173_u64;
    for _ in 0..count {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let ip = Ipv4Addr::new(
            (state >> 24) as u8,
            (state >> 32) as u8,
            (state >> 40) as u8,
            (state >> 48) as u8,
        );
        ips.push(IpAddr::V4(ip));
    }
    ips
}

// Single-threaded
pub fn bench_maxminddb<T>(ips: &[IpAddr], reader: &maxminddb::Reader<T>)
where
    T: AsRef<[u8]>,
{
    for ip in ips.iter() {
        let result = reader.lookup(*ip).unwrap();
        if result.has_data() {
            let _: geoip2::City = result.decode().unwrap().unwrap();
        }
    }
}

// Using rayon for parallel execution
pub fn bench_par_maxminddb<T>(ips: &[IpAddr], reader: &maxminddb::Reader<T>)
where
    T: AsRef<[u8]> + std::marker::Sync,
{
    ips.par_iter().for_each(|ip| {
        let result = reader.lookup(*ip).unwrap();
        if result.has_data() {
            let _: geoip2::City = result.decode().unwrap().unwrap();
        }
    });
}

const DB_FILE: &str = "GeoLite2-City.mmdb";

pub fn criterion_benchmark(c: &mut Criterion) {
    let ips = generate_ipv4(100);
    #[cfg(not(feature = "mmap"))]
    let reader = maxminddb::Reader::open_readfile(DB_FILE).unwrap();
    #[cfg(feature = "mmap")]
    // SAFETY: The benchmark database file will not be modified during the benchmark.
    let reader = unsafe { maxminddb::Reader::open_mmap(DB_FILE) }.unwrap();

    c.bench_function("maxminddb", |b| b.iter(|| bench_maxminddb(&ips, &reader)));
}

pub fn criterion_par_benchmark(c: &mut Criterion) {
    let ips = generate_ipv4(100);
    #[cfg(not(feature = "mmap"))]
    let reader = maxminddb::Reader::open_readfile(DB_FILE).unwrap();
    #[cfg(feature = "mmap")]
    // SAFETY: The benchmark database file will not be modified during the benchmark.
    let reader = unsafe { maxminddb::Reader::open_mmap(DB_FILE) }.unwrap();

    c.bench_function("maxminddb_par", |b| {
        b.iter(|| bench_par_maxminddb(&ips, &reader))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20);

    targets = criterion_benchmark, criterion_par_benchmark
}
criterion_main!(benches);
