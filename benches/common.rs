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

pub fn open_reader(db_file: &str) -> maxminddb::Reader<impl AsRef<[u8]>> {
    #[cfg(not(feature = "mmap"))]
    return maxminddb::Reader::open_readfile(db_file).unwrap();

    #[cfg(feature = "mmap")]
    // SAFETY: The benchmark database file will not be modified during the benchmark.
    return unsafe { maxminddb::Reader::open_mmap(db_file) }.unwrap();
}
