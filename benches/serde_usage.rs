use criterion::{criterion_group, criterion_main, Criterion};
use maxminddb::geoip2;
use maxminddb::{LookupResult, PathElement, Reader};
use std::hint::black_box;

use std::net::IpAddr;

mod common;
use common::generate_ipv4;

const DB_FILE: &str = "GeoLite2-City.mmdb";

fn cache_lookups<'a, T>(ips: &[IpAddr], reader: &'a Reader<T>) -> Vec<LookupResult<'a, T>>
where
    T: AsRef<[u8]>,
{
    ips.iter()
        .map(|ip| reader.lookup(*ip).unwrap())
        .filter(|r| r.has_data())
        .collect()
}

fn bench_lookup_only<T>(ips: &[IpAddr], reader: &Reader<T>)
where
    T: AsRef<[u8]>,
{
    for ip in ips {
        let result = reader.lookup(*ip).unwrap();
        black_box(result.has_data());
    }
}

fn bench_decode_city_only<T>(results: &[LookupResult<'_, T>])
where
    T: AsRef<[u8]>,
{
    for result in results {
        let city: Option<geoip2::City<'_>> = result.decode().unwrap();
        black_box(city);
    }
}

fn bench_decode_country_only<T>(results: &[LookupResult<'_, T>])
where
    T: AsRef<[u8]>,
{
    for result in results {
        let country: Option<geoip2::Country<'_>> = result.decode().unwrap();
        black_box(country);
    }
}

fn bench_decode_path_country_iso<T>(results: &[LookupResult<'_, T>])
where
    T: AsRef<[u8]>,
{
    let path = [PathElement::Key("country"), PathElement::Key("iso_code")];
    for result in results {
        let value: Option<&str> = result.decode_path(&path).unwrap();
        black_box(value);
    }
}

fn bench_decode_path_city_name<T>(results: &[LookupResult<'_, T>])
where
    T: AsRef<[u8]>,
{
    let path = [
        PathElement::Key("city"),
        PathElement::Key("names"),
        PathElement::Key("en"),
    ];
    for result in results {
        let value: Option<&str> = result.decode_path(&path).unwrap();
        black_box(value);
    }
}

pub fn serde_usage_benchmark(c: &mut Criterion) {
    let ips = generate_ipv4(100);

    #[cfg(not(feature = "mmap"))]
    let reader = Reader::open_readfile(DB_FILE).unwrap();
    #[cfg(feature = "mmap")]
    // SAFETY: The benchmark database file will not be modified during the benchmark.
    let reader = unsafe { Reader::open_mmap(DB_FILE) }.unwrap();

    let cached_results = cache_lookups(&ips, &reader);

    c.bench_function("serde_usage/lookup_only", |b| {
        b.iter(|| bench_lookup_only(&ips, &reader))
    });
    c.bench_function("serde_usage/decode_city_only", |b| {
        b.iter(|| bench_decode_city_only(&cached_results))
    });
    c.bench_function("serde_usage/decode_country_only", |b| {
        b.iter(|| bench_decode_country_only(&cached_results))
    });
    c.bench_function("serde_usage/decode_path_country_iso", |b| {
        b.iter(|| bench_decode_path_country_iso(&cached_results))
    });
    c.bench_function("serde_usage/decode_path_city_name", |b| {
        b.iter(|| bench_decode_path_city_name(&cached_results))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = serde_usage_benchmark
}
criterion_main!(benches);
