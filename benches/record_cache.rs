//! Run with `cargo bench --bench record_cache -- /path/to/database.mmdb`.
//! Set MMDB_CACHE_SCHEMA to city (default), country, isp, anonymous, or value.
//! MMDB_CACHE_WORKLOAD selects mixed_random or mixed_hits (default: both).
//! See README for workload distributions and separate allocation measurements.

use maxminddb::{geoip2, Reader, WithinOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// A separate build enables accounting. It measures allocation sizes, not
// speed; the compiler removes accounting from the normal timing build.
const TRACK: bool = option_env!("MMDB_TRACK_ALLOC").is_some();
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

// SAFETY: All allocation operations forward the original pointer/layout to
// System. The optional counters neither inspect nor modify allocated memory.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if TRACK && !ptr.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACK {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if TRACK && !ptr.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, size) };
        if TRACK && !ptr.is_null() {
            let now = if size >= layout.size() {
                LIVE.fetch_add(size - layout.size(), Ordering::Relaxed) + size - layout.size()
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed) - layout.size() + size
            };
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }
}

fn random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut n = *state;
    n = (n ^ (n >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    n = (n ^ (n >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    n ^ (n >> 31)
}

fn measure(mut operation: impl FnMut(), millis: u64, queries: usize) -> Value {
    operation();
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let mut count = 0;
        while count == 0 || start.elapsed() < Duration::from_millis(millis) {
            operation();
            count += 1;
        }
        samples.push(start.elapsed().as_nanos() as f64 / (count * queries) as f64);
    }
    samples.sort_by(f64::total_cmp);
    json!({"median_ns":samples[2],"samples_ns":samples})
}

fn production_sample<'a, T: Deserialize<'a> + Serialize>(
    reader: &'a Reader<&'a [u8]>,
    ips: &[IpAddr],
    millis: u64,
) -> Value {
    let initialization = if TRACK {
        Value::Null
    } else {
        measure(
            || {
                black_box(reader.record_cache::<T>());
            },
            millis,
            1,
        )
    };
    let before = LIVE.load(Ordering::Relaxed);
    let mut cache = reader.record_cache::<T>();
    let base_bytes = std::mem::size_of_val(&cache) + 2 * std::mem::size_of::<Option<T>>();
    for &ip in ips.iter().take(512).cycle().take(1024) {
        let expected = reader.lookup(ip).unwrap();
        let actual = cache.lookup(ip).unwrap();
        assert_eq!(actual.offset(), expected.offset());
        assert_eq!(actual.network().unwrap(), expected.network().unwrap());
        assert_eq!(
            actual.data().map(|v| serde_json::to_value(v).unwrap()),
            expected
                .decode::<T>()
                .unwrap()
                .map(|v| serde_json::to_value(v).unwrap())
        );
    }
    for &ip in ips {
        if let Some(value) = cache.lookup(ip).unwrap().data() {
            black_box(value);
        }
    }
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    for &ip in ips {
        if let Some(value) = cache.lookup(ip).unwrap().data() {
            black_box(value);
        }
    }
    let retained =
        TRACK.then(|| LIVE.load(Ordering::Relaxed) - before + std::mem::size_of_val(&cache));
    let peak = TRACK.then(|| PEAK.load(Ordering::Relaxed) - before + std::mem::size_of_val(&cache));
    let timing = if TRACK {
        Value::Null
    } else {
        measure(
            || {
                for &ip in ips {
                    if let Some(value) = cache.lookup(black_box(ip)).unwrap().data() {
                        black_box(value);
                    }
                }
            },
            millis,
            ips.len(),
        )
    };
    json!({"timing":timing,"initialization":initialization,"base_bytes":base_bytes,"retained_bytes":retained,"peak_bytes":peak})
}

fn generate(reader: &Reader<&[u8]>, count: usize, state: &mut u64) -> Vec<(String, Vec<IpAddr>)> {
    let mut ips = Vec::with_capacity(2 * count);
    for _ in 0..count {
        ips.push(IpAddr::V4(Ipv4Addr::from((random(state) >> 32) as u32)));
        ips.push(IpAddr::V6(Ipv6Addr::from(
            (u128::from(random(state)) << 64) | u128::from(random(state)),
        )));
    }
    for i in (1..ips.len()).rev() {
        ips.swap(i, random(state) as usize % (i + 1));
    }
    let mut workloads = vec![("mixed_random".into(), ips)];
    if std::env::var("MMDB_CACHE_WORKLOAD").as_deref() != Ok("mixed_random") {
        let mut hits = [Vec::new(), Vec::new()];
        let mut seen = [0usize; 2];
        for record in reader.networks(WithinOptions::default()).unwrap() {
            let network = record.unwrap().network().unwrap();
            let family = usize::from(network.is_ipv6());
            seen[family] += 1;
            if hits[family].len() < 8192 {
                hits[family].push(network);
            } else {
                let slot = random(state) as usize % seen[family];
                if slot < hits[family].len() {
                    hits[family][slot] = network;
                }
            }
        }
        if !hits[0].is_empty() && !hits[1].is_empty() {
            let size = hits[0].len().min(hits[1].len());
            let mut ips: Vec<_> = hits[0]
                .iter()
                .take(size)
                .zip(hits[1].iter().take(size))
                .flat_map(|(v4, v6)| [v4.ip(), v6.ip()])
                .collect();
            for i in (1..ips.len()).rev() {
                ips.swap(i, random(state) as usize % (i + 1));
            }
            workloads.push(("mixed_hits".into(), ips));
        }
    }
    workloads
}

fn run<'a, T: Deserialize<'a> + Serialize>(
    reader: &'a Reader<&'a [u8]>,
    workloads: &[(String, Vec<IpAddr>)],
    millis: u64,
) -> Value {
    let mut results = serde_json::Map::new();
    for (name, ips) in workloads {
        if std::env::var("MMDB_CACHE_WORKLOAD").is_ok_and(|filter| name != &filter) {
            continue;
        }
        let mut found = [0usize; 2];
        for &ip in ips {
            if reader.lookup(ip).unwrap().has_data() {
                found[usize::from(ip.is_ipv6())] += 1;
            }
        }
        let baseline = || {
            if TRACK {
                Value::Null
            } else {
                measure(
                    || {
                        for &ip in ips {
                            if let Some(value) =
                                reader.lookup(black_box(ip)).unwrap().decode::<T>().unwrap()
                            {
                                black_box(&value);
                            }
                        }
                    },
                    millis,
                    ips.len(),
                )
            }
        };
        let before = baseline();
        let cached = production_sample::<T>(reader, ips, millis);
        results.insert(
            name.clone(),
            json!({
                "queries":ips.len(), "ipv4_found":found[0], "ipv6_found":found[1],
                "uncached_before":before, "cached":cached, "uncached_after":baseline(),
            }),
        );
    }
    json!({"record_bytes":std::mem::size_of::<T>(),"workloads":results})
}

fn main() {
    let path = std::env::args()
        .skip(1)
        .find(|s| s != "--bench")
        .expect("database path");
    let bytes = std::fs::read(&path).unwrap();
    let open = || Reader::from_source(black_box(bytes.as_slice())).unwrap();
    let reader = open();
    let seed =
        std::env::var("MMDB_CACHE_SEED").map_or(0x5eed_2024_cafe_babe, |s| s.parse().unwrap());
    let count = std::env::var("MMDB_CACHE_COUNT").map_or(65_536, |s| s.parse().unwrap());
    assert!(count > 0);
    let millis = std::env::var("MMDB_BENCH_MS").map_or(100, |s| s.parse().unwrap());
    let construction = if TRACK {
        Value::Null
    } else {
        measure(
            || {
                black_box(open());
            },
            millis,
            1,
        )
    };
    let mut state = seed;
    let workloads = generate(&reader, count, &mut state);
    let schema = std::env::var("MMDB_CACHE_SCHEMA").unwrap_or_else(|_| "city".into());
    let results = match schema.as_str() {
        "city" => run::<geoip2::City>(&reader, &workloads, millis),
        "country" => run::<geoip2::Country>(&reader, &workloads, millis),
        "isp" => run::<geoip2::Isp>(&reader, &workloads, millis),
        "anonymous" => run::<geoip2::AnonymousIp>(&reader, &workloads, millis),
        "value" => run::<Value>(&reader, &workloads, millis),
        _ => panic!("unknown schema"),
    };
    println!(
        "{}",
        json!({
            "database_type":reader.metadata().database_type,"database_bytes":bytes.len(),
            "nodes":reader.metadata().node_count,"record_size":reader.metadata().record_size,
            "build_epoch":reader.metadata().build_epoch,"schema":schema,"open_buffer":construction,
            "allocation_tracking":TRACK,"seed":seed,"sample_ms":millis,"results":results,
        })
    );
}
