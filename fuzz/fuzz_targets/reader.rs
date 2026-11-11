#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use maxminddb::{LookupResult, PathElement, Reader, WithinOptions};

mod common;

// The mixed database has an IPv6 tree with an IPv4 subtree, so patches also
// reach the IPv6 index and the IPv4 index built below the IPv4 start node.
const SEED_DATABASES: [&[u8]; 2] = [
    include_bytes!("../../test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb"),
    include_bytes!("../../test-data/test-data/MaxMind-DB-test-mixed-24.mmdb"),
];

fn exercise_lookup<S>(lookup: &LookupResult<'_, S>)
where
    S: AsRef<[u8]>,
{
    let _ = lookup.network();
    let _ = lookup.decode::<common::FuzzValue>();

    let map_path = [PathElement::Key("country"), PathElement::Key("iso_code")];
    let _ = lookup.decode_path::<common::FuzzValue>(&map_path);

    let array_path = [PathElement::Key("array"), PathElement::Index(0)];
    let _ = lookup.decode_path::<common::FuzzValue>(&array_path);
}

fn exercise_database(data: &[u8], address_seed: &[u8]) {
    let Ok(reader) = Reader::from_source(data) else {
        return;
    };

    let _ = reader.verify();
    let direct = Reader::from_source(data).unwrap().without_lookup_index();

    let mut addresses = vec![
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(89, 160, 20, 128)),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::from(u128::MAX)),
    ];
    // Let the fuzzer choose addresses too, so it can reach every index slot.
    for chunk in address_seed.rchunks(16).take(4) {
        let mut bytes = [0u8; 16];
        bytes[..chunk.len()].copy_from_slice(chunk);
        addresses.push(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )));
        addresses.push(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    let describe = |lookup: &Result<LookupResult<'_, &[u8]>, maxminddb::MaxMindDbError>| {
        lookup
            .as_ref()
            .map(|result| (result.offset(), result.network().map_err(|e| e.to_string())))
            .map_err(|e| e.to_string())
    };
    for address in addresses {
        let indexed = reader.lookup(address);
        assert_eq!(describe(&indexed), describe(&direct.lookup(address)));
        if let Ok(lookup) = &indexed {
            exercise_lookup(lookup);
        }
    }

    if let Ok(networks) = reader.networks(WithinOptions::default()) {
        for lookup in networks.take(256).flatten() {
            exercise_lookup(&lookup);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Exercise arbitrary files for parser and metadata coverage.
    exercise_database(data, data);

    // Also interpret the input as byte patches against a valid tiny database.
    // This keeps enough structure intact for mutations to reach search-tree and
    // data-section decoding quickly, without needing a checked-in corpus copy.
    for seed in SEED_DATABASES {
        let mut database = seed.to_vec();
        for patch in data.chunks_exact(3) {
            let offset = usize::from(u16::from_be_bytes([patch[0], patch[1]])) % database.len();
            database[offset] = patch[2];
        }
        exercise_database(&database, data);
    }
});
