use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use serde::Deserialize;

use maxminddb::{MaxMindDbError, Reader};

use crate::common::{open_test_data_reader, TEST_DATABASE_CONFIGS};

#[test]
fn test_pointers_in_metadata() {
    let reader = open_test_data_reader("MaxMind-DB-test-metadata-pointers.mmdb");

    assert_eq!(
        reader.metadata().database_type,
        "Lots of pointers in metadata"
    );
    assert_eq!(
        reader.metadata().description["en"],
        "Lots of pointers in metadata"
    );
    assert_eq!(
        reader.metadata().description["es"],
        "Lots of pointers in metadata"
    );
    assert_eq!(
        reader.metadata().description["zh"],
        "Lots of pointers in metadata"
    );

    reader.verify().unwrap();
}

#[test]
fn test_broken_database() {
    let r = open_test_data_reader("GeoIP2-City-Test-Broken-Double-Format.mmdb");
    let ip: IpAddr = "2001:220::".parse().unwrap();

    #[derive(Deserialize, Debug)]
    struct TestType {}

    let lookup = r.lookup(ip).unwrap();
    if lookup.has_data() {
        match lookup.decode::<TestType>() {
            Err(e) => assert!(matches!(
                e,
                MaxMindDbError::InvalidDatabase { .. } // Check variant, message might vary slightly
            )),
            Ok(_) => panic!("Unexpected success with broken data"),
        }
    } else {
        panic!("Expected IP to be found (with broken data)");
    }
}

#[test]
fn test_missing_database() {
    let r = Reader::open_readfile("file-does-not-exist.mmdb");
    match r {
        Ok(_) => panic!("Received Reader when opening non-existent file"),
        Err(e) => assert!(matches!(e, MaxMindDbError::Io(_))), // Specific message might vary by OS/locale
    }
}

#[test]
fn test_non_database() {
    let r = Reader::open_readfile("README.md");
    match r {
        Ok(_) => panic!("Received Reader when opening a non-MMDB file"),
        Err(e) => assert!(
            matches!(&e, MaxMindDbError::InvalidDatabase { message, .. } if message == "could not find MaxMind DB metadata in file"),
            "Expected InvalidDatabase error with specific message, but got: {:?}",
            e
        ),
    }
}

#[test]
fn test_invalid_node_count_database() {
    let r = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test-Invalid-Node-Count.mmdb");
    match r {
        Ok(_) => panic!("Received Reader when opening database with invalid node count"),
        Err(e) => assert!(
            matches!(&e, MaxMindDbError::InvalidDatabase { message, .. } if message == "the MaxMind DB file's search tree extends beyond the metadata section"),
            "Expected InvalidDatabase error about search tree layout, but got: {:?}",
            e
        ),
    }
}

/// Create Reader by explicitly reading the entire file into a buffer.
#[test]
fn test_reader_readfile() {
    for (record_size, ip_version) in TEST_DATABASE_CONFIGS {
        let reader = open_test_data_reader(&format!(
            "MaxMind-DB-test-ipv{ip_version}-{record_size}.mmdb"
        ));

        check_metadata(&reader, *ip_version, *record_size);
        check_ip(&reader, *ip_version);
    }
}

#[test]
#[cfg(feature = "mmap")]
fn test_reader_mmap() {
    for (record_size, ip_version) in TEST_DATABASE_CONFIGS {
        let filename =
            format!("test-data/test-data/MaxMind-DB-test-ipv{ip_version}-{record_size}.mmdb");
        // SAFETY: The test database file will not be modified during the test.
        let reader = unsafe { Reader::open_mmap(filename) }.unwrap();

        check_metadata(&reader, *ip_version, *record_size);
        check_ip(&reader, *ip_version);
    }
}

#[test]
fn test_metadata_build_time_conversion() {
    let reader = open_test_data_reader("GeoIP2-City-Test.mmdb");

    assert_eq!(
        reader.metadata().build_time().unwrap(),
        UNIX_EPOCH + Duration::from_secs(reader.metadata().build_epoch)
    );
}

#[test]
fn test_metadata_build_time_rejects_uint64_max_epoch() {
    let err =
        Reader::open_readfile("test-data/bad-data/libmaxminddb/libmaxminddb-uint64-max-epoch.mmdb")
            .unwrap_err();

    assert!(
        matches!(
            err,
            MaxMindDbError::InvalidDatabase { ref message, .. }
                if message
                    == "build_epoch - Unix timestamp is too large to represent as SystemTime: 18446744073709551615"
        ),
        "Expected InvalidDatabase error for unrepresentable build_epoch, got {err:?}"
    );
}

#[test]
fn test_reader_metadata_accessor_returns_validated_metadata() {
    let reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");

    assert_eq!(reader.metadata().record_size, 24);
    assert_eq!(reader.metadata().ip_version, 4);
    assert_eq!(reader.metadata().database_type, "Test");
}

#[test]
fn test_metadata_payload_amplification_is_rejected() {
    let result =
        Reader::open_readfile("test-data/test-data/MaxMind-DB-test-metadata-payload-limit.mmdb");
    assert!(
        matches!(&result, Err(MaxMindDbError::ResourceLimit { message, .. })
            if message.contains("maximum size of data structure string and bytes")),
        "unexpected metadata amplification result: {result:?}"
    );
}

fn check_metadata<S: AsRef<[u8]>>(reader: &Reader<S>, ip_version: usize, record_size: usize) {
    let metadata = reader.metadata();

    assert_eq!(metadata.binary_format_major_version, 2_u16);
    assert_eq!(metadata.binary_format_minor_version, 0_u16);
    assert!(metadata.build_epoch >= 1_397_457_605);
    assert_eq!(metadata.database_type, "Test".to_string());

    assert_eq!(
        *metadata.description[&"en".to_string()],
        "Test Database".to_string()
    );
    assert_eq!(
        *metadata.description[&"zh".to_string()],
        "Test Database Chinese".to_string()
    );

    assert_eq!(metadata.ip_version, ip_version as u16);
    assert_eq!(metadata.languages, vec!["en".to_string(), "zh".to_string()]);

    if ip_version == 4 {
        assert_eq!(metadata.node_count, 139)
    } else {
        assert_eq!(metadata.node_count, 376)
    }

    assert_eq!(metadata.record_size, record_size as u16)
}

fn check_ip<S: AsRef<[u8]>>(reader: &Reader<S>, ip_version: usize) {
    let subnets = match ip_version {
        6 => [
            "::1:ffff:ffff",
            "::2:0:0",
            "::2:0:0",
            "::2:0:0",
            "::2:0:0",
            "::2:0:40",
            "::2:0:40",
            "::2:0:40",
            "::2:0:50",
            "::2:0:50",
            "::2:0:50",
            "::2:0:58",
            "::2:0:58",
        ],
        _ => [
            "1.1.1.1", "1.1.1.2", "1.1.1.2", "1.1.1.4", "1.1.1.4", "1.1.1.4", "1.1.1.4", "1.1.1.8",
            "1.1.1.8", "1.1.1.8", "1.1.1.16", "1.1.1.16", "1.1.1.16",
        ],
    };

    #[derive(Deserialize, Debug, PartialEq)]
    struct IpType {
        ip: String,
    }

    // Test lookups that are expected to succeed
    for subnet in &subnets {
        let ip: IpAddr = subnet.parse().unwrap();
        let lookup = reader.lookup(ip);

        assert!(
            lookup.is_ok(),
            "Lookup failed unexpectedly for {}: {:?}",
            subnet,
            lookup.err()
        );
        let lookup = lookup.unwrap();
        assert!(
            lookup.has_data(),
            "Lookup for {} returned not found unexpectedly",
            subnet
        );
        let value: IpType = lookup.decode().unwrap().unwrap();

        // The value stored is often the network address, not the specific IP looked up
        // We need to parse the found IP and the subnet IP to check containment or equality.
        // For the specific MaxMind-DB-test-ipv* files, the stored value IS the looked-up IP string.
        assert_eq!(value.ip, *subnet);
    }

    // Test lookups that are expected to return "not found"
    let no_record = ["1.1.1.33", "255.254.253.123", "89fa::"];

    for &address in &no_record {
        if ip_version == 4 && address == "89fa::" {
            continue; // Skip IPv6 address if testing IPv4 db
        }
        if ip_version == 6 && address != "89fa::" {
            continue; // Skip IPv4 addresses if testing IPv6 db
        }

        let ip: IpAddr = address.parse().unwrap();
        let lookup = reader.lookup(ip).unwrap();

        assert!(
            !lookup.has_data(),
            "Expected not found for address {}, but it was found",
            address
        );
    }
}
