use std::cell::Cell;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

use serde::Deserialize;

use maxminddb::{geoip2, MaxMindDbError, Reader, WithinOptions};

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
fn test_reader_rejects_repeated_metadata_keys() {
    for (file, key) in [
        ("libmaxminddb-repeated-metadata-key.mmdb", "database_type"),
        ("libmaxminddb-repeated-node-count.mmdb", "node_count"),
        ("libmaxminddb-repeated-pointer-key.mmdb", "database_type"),
        ("libmaxminddb-repeated-description-key.mmdb", "en"),
    ] {
        let path = format!("test-data/bad-data/libmaxminddb/{file}");
        let err = Reader::open_readfile(&path).unwrap_err();

        assert!(
            matches!(
                err,
                MaxMindDbError::Decoding { ref message, .. }
                    if message.contains("duplicate") && message.contains(key)
            ),
            "Expected duplicate key error for {file}, got {err:?}"
        );
    }
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

/// A source whose `as_ref` returns a shorter slice once `shrunk` is set.
///
/// `AsRef` is a safe trait, so nothing stops a source from doing this. The
/// reader must not trust lengths it cached when it was opened.
#[derive(Debug)]
struct ShrinkingSource {
    bytes: Vec<u8>,
    shrunk_len: usize,
    shrunk: Rc<Cell<bool>>,
}

impl AsRef<[u8]> for ShrinkingSource {
    fn as_ref(&self) -> &[u8] {
        if self.shrunk.get() {
            &self.bytes[..self.shrunk_len]
        } else {
            &self.bytes
        }
    }
}

/// Opens `database` with a source that, once the returned flag is set, keeps
/// only the search tree, the data section separator, and the first
/// `data_bytes` bytes of the data section.
fn open_shrinking_reader(
    database: &str,
    data_bytes: usize,
) -> (Reader<ShrinkingSource>, Rc<Cell<bool>>) {
    let bytes = std::fs::read(format!("test-data/test-data/{database}")).unwrap();
    let metadata = Reader::from_source(bytes.as_slice())
        .unwrap()
        .metadata()
        .clone();
    let tree_size = metadata.node_count as usize * metadata.record_size as usize / 4;
    let shrunk = Rc::new(Cell::new(false));
    let reader = Reader::from_source(ShrinkingSource {
        bytes,
        shrunk_len: tree_size + 16 + data_bytes,
        shrunk: Rc::clone(&shrunk),
    })
    .unwrap();
    (reader, shrunk)
}

fn assert_shrunk_source_error(err: MaxMindDbError) {
    assert!(
        matches!(err, MaxMindDbError::InvalidDatabase { .. }),
        "expected InvalidDatabase, got {err:?}"
    );
    assert!(
        err.to_string().contains("shorter"),
        "unexpected error message: {err}"
    );
}

#[test]
fn test_source_that_shrinks_after_lookup() {
    // 0 drops the whole data section; 1 and 100 cut into it. Each is
    // rejected by the data section bounds check before decoding starts.
    for data_bytes in [0, 1, 100] {
        let (reader, shrunk) = open_shrinking_reader("GeoIP2-City-Test.mmdb", data_bytes);
        let ip: IpAddr = "89.160.20.128".parse().unwrap();
        let result = reader.lookup(ip).unwrap();
        assert!(result.has_data());

        shrunk.set(true);

        let err = result.decode::<geoip2::City>().unwrap_err();
        assert_shrunk_source_error(err);

        let err = result
            .decode_path::<String>(&maxminddb::path!["city", "names", "en"])
            .unwrap_err();
        assert_shrunk_source_error(err);
    }
}

#[test]
fn test_source_that_drops_only_metadata_still_decodes() {
    let bytes = std::fs::read("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let marker = b"\xab\xcd\xefMaxMind.com";
    let data_section_end = bytes
        .windows(marker.len())
        .rposition(|w| w == marker)
        .expect("metadata marker");
    let metadata = Reader::from_source(bytes.as_slice())
        .unwrap()
        .metadata()
        .clone();
    let pointer_base = metadata.node_count as usize * metadata.record_size as usize / 4 + 16;

    // Keeping exactly the data section, without the metadata marker or the
    // metadata, is still enough to decode records.
    let (reader, shrunk) =
        open_shrinking_reader("GeoIP2-City-Test.mmdb", data_section_end - pointer_base);
    let ip: IpAddr = "89.160.20.128".parse().unwrap();
    let result = reader.lookup(ip).unwrap();

    shrunk.set(true);

    let city = result.decode::<geoip2::City>().unwrap().unwrap();
    assert_eq!(city.city.names.english, Some("Linköping"));
    let name: Option<String> = result
        .decode_path(&maxminddb::path!["city", "names", "en"])
        .unwrap();
    assert_eq!(name.as_deref(), Some("Linköping"));
}

#[test]
fn test_source_that_shrinks_during_within() {
    for data_bytes in [0, 1, 100] {
        // Skipping empty values decodes each record while iterating.
        let (reader, shrunk) = open_shrinking_reader("GeoIP2-City-Test.mmdb", data_bytes);
        let mut iter = reader
            .networks(WithinOptions::default().skip_empty_values())
            .unwrap();

        shrunk.set(true);

        let err = iter.next().expect("the database has networks").unwrap_err();
        assert_shrunk_source_error(err);

        // With default options, iteration only reads the tree, and decoding
        // the yielded result hits the check.
        let (reader, shrunk) = open_shrinking_reader("GeoIP2-City-Test.mmdb", data_bytes);
        let mut iter = reader.networks(WithinOptions::default()).unwrap();

        shrunk.set(true);

        let result = iter.next().expect("the database has networks").unwrap();
        let err = result.decode::<geoip2::City>().unwrap_err();
        assert_shrunk_source_error(err);
    }
}

/// Builds a one-node IPv4 database with 24-bit records and no data. Both
/// records point at the no-data sentinel. `languages` is written to the
/// metadata only when it is `Some`.
fn one_node_database(languages: Option<&[&str]>) -> Vec<u8> {
    fn header(kind: u8, size: usize, bytes: &mut Vec<u8>) {
        assert!(size < 29);
        if kind < 8 {
            bytes.push((kind << 5) | size as u8);
        } else {
            bytes.push(size as u8);
            bytes.push(kind - 7);
        }
    }
    fn string(value: &str, bytes: &mut Vec<u8>) {
        header(2, value.len(), bytes);
        bytes.extend_from_slice(value.as_bytes());
    }
    fn uint(kind: u8, value: u64, bytes: &mut Vec<u8>) {
        let be = value.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        header(kind, be.len() - skip, bytes);
        bytes.extend_from_slice(&be[skip..]);
    }

    // One node; both 24-bit records equal node_count, meaning no data.
    let mut bytes = vec![0, 0, 1, 0, 0, 1];
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(b"\xab\xcd\xefMaxMind.com");

    header(7, if languages.is_some() { 9 } else { 8 }, &mut bytes);
    string("binary_format_major_version", &mut bytes);
    uint(5, 2, &mut bytes);
    string("binary_format_minor_version", &mut bytes);
    uint(5, 0, &mut bytes);
    string("build_epoch", &mut bytes);
    uint(9, 1_700_000_000, &mut bytes);
    string("database_type", &mut bytes);
    string("Test", &mut bytes);
    string("description", &mut bytes);
    header(7, 1, &mut bytes);
    string("en", &mut bytes);
    string("Test Database", &mut bytes);
    string("ip_version", &mut bytes);
    uint(5, 4, &mut bytes);
    if let Some(languages) = languages {
        string("languages", &mut bytes);
        header(11, languages.len(), &mut bytes);
        for language in languages {
            string(language, &mut bytes);
        }
    }
    string("node_count", &mut bytes);
    uint(6, 1, &mut bytes);
    string("record_size", &mut bytes);
    uint(5, 24, &mut bytes);
    bytes
}

#[test]
fn test_reader_opens_database_without_languages() {
    let reader = Reader::from_source(one_node_database(None)).unwrap();

    let metadata = reader.metadata();
    assert!(metadata.languages.is_empty());
    assert_eq!(metadata.database_type, "Test");
    assert_eq!(metadata.node_count, 1);
    assert!(!reader
        .lookup("1.1.1.1".parse().unwrap())
        .unwrap()
        .has_data());
    reader.verify().unwrap();
}

#[test]
fn test_reader_reads_languages_when_present() {
    let reader = Reader::from_source(one_node_database(Some(&["en", "zh"]))).unwrap();

    assert_eq!(reader.metadata().languages, vec!["en", "zh"]);
    reader.verify().unwrap();
}
