//! Run with `cargo bench --bench lookup_workloads -- /path/to/database.mmdb`.
//! Emits JSON for before/after comparisons. Pin the process to the same CPU.

use maxminddb::{geoip2, Reader, WithinOptions};
use serde_json::json;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

fn random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut n = *state;
    n = (n ^ (n >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    n = (n ^ (n >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    n ^ (n >> 31)
}

fn measure(mut operation: impl FnMut(), batch: usize) -> Vec<f64> {
    let millis = std::env::var("MMDB_BENCH_MS")
        .map(|s| s.parse().unwrap())
        .unwrap_or(200);
    for _ in 0..batch {
        operation();
    }
    (0..5)
        .map(|_| {
            let start = Instant::now();
            let mut iterations = 0;
            while start.elapsed() < Duration::from_millis(millis) || iterations == 0 {
                for _ in 0..batch {
                    operation();
                }
                iterations += batch;
            }
            start.elapsed().as_nanos() as f64 / iterations as f64
        })
        .collect()
}

fn main() {
    let path = std::env::args()
        .skip(1)
        .find(|arg| arg != "--bench")
        .unwrap_or_else(|| "GeoLite2-City.mmdb".into());
    let bytes = std::fs::read(&path).unwrap();
    let indexed = std::env::var_os("MMDB_BENCH_INDEX").is_some();
    let open = || {
        let reader = Reader::from_source(black_box(bytes.as_slice())).unwrap();
        if indexed {
            reader.with_lookup_index()
        } else {
            reader
        }
    };
    let reader = open();
    let mut state = 0x5eed_2024_cafe_babe;
    let v4: Vec<_> = (0..65_536)
        .map(|_| IpAddr::V4(Ipv4Addr::from((random(&mut state) >> 32) as u32)))
        .collect();
    let v6: Vec<_> = (0..65_536)
        .map(|_| {
            IpAddr::V6(Ipv6Addr::from(
                (u128::from(random(&mut state)) << 64) | u128::from(random(&mut state)),
            ))
        })
        .collect();
    // Reservoir-sample records across the entire database rather than taking
    // neighboring prefixes. These samples weight networks equally, not IPs.
    let mut hits = [Vec::new(), Vec::new()];
    let mut seen = [0usize; 2];
    for result in reader.networks(WithinOptions::default()).unwrap() {
        let network = result.unwrap().network().unwrap();
        let ip = network.ip();
        let family = usize::from(ip.is_ipv6());
        seen[family] += 1;
        let sample = &mut hits[family];
        if sample.len() < 8192 {
            sample.push(ip);
        } else {
            let slot = random(&mut state) as usize % seen[family];
            if slot < sample.len() {
                sample[slot] = ip;
            }
        }
    }
    let mut results = serde_json::Map::new();
    let filter = std::env::var("MMDB_BENCH_FILTER").unwrap_or_default();
    let mut record = |name: &str, samples: Vec<f64>, operations: usize| {
        let mut samples: Vec<_> = samples.into_iter().map(|n| n / operations as f64).collect();
        samples.sort_by(f64::total_cmp);
        results.insert(
            name.into(),
            json!({"median_ns": samples[2], "samples_ns": samples}),
        );
    };
    let mut workloads = vec![("v4_random", &v4), ("v4_hits", &hits[0])];
    if reader.metadata().ip_version == 6 {
        workloads.extend([("v6_random", &v6), ("v6_hits", &hits[1])]);
    }
    let mut hit_counts = serde_json::Map::new();
    for (name, ips) in workloads {
        if ips.is_empty() {
            continue;
        }
        let hits = ips
            .iter()
            .filter(|&&ip| reader.lookup(ip).unwrap().has_data())
            .count();
        hit_counts.insert(name.into(), json!({"hits": hits, "queries": ips.len()}));
        let tree_name = format!("tree/{name}");
        if tree_name.contains(&filter) {
            record(
                &tree_name,
                measure(
                    || {
                        for &ip in ips {
                            black_box(reader.lookup(black_box(ip)).unwrap().has_data());
                        }
                    },
                    1,
                ),
                ips.len(),
            );
        }
        let decode_name = format!("lookup_decode/{name}");
        if decode_name.contains(&filter) {
            record(
                &decode_name,
                measure(
                    || {
                        for &ip in ips {
                            let lookup = reader.lookup(black_box(ip)).unwrap();
                            if let Some(city) = lookup.decode::<geoip2::City>().unwrap() {
                                black_box(city);
                            }
                        }
                    },
                    1,
                ),
                ips.len(),
            );
        }
        if name.ends_with("hits") && format!("decode/{name}").contains(&filter) {
            let lookups: Vec<_> = ips.iter().map(|&ip| reader.lookup(ip).unwrap()).collect();
            record(
                &format!("decode/{name}"),
                measure(
                    || {
                        for lookup in &lookups {
                            black_box(lookup.decode::<geoip2::City>().unwrap().unwrap());
                        }
                    },
                    1,
                ),
                ips.len(),
            );
        }
    }
    if "open_buffer".contains(&filter) {
        record(
            "open_buffer",
            measure(
                || {
                    black_box(open());
                },
                10,
            ),
            1,
        );
    }
    println!(
        "{}",
        json!({
            "path": path,
        "indexed": indexed,
            "bytes": bytes.len(),
            "node_count": reader.metadata().node_count,
            "record_size": reader.metadata().record_size,
            "build_epoch": reader.metadata().build_epoch,
            "workloads": hit_counts,
            "results": results,
        })
    );
}
