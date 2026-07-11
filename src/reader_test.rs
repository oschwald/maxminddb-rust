use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use ipnetwork::IpNetwork;
use serde::Deserialize;
use serde_json::json;

use crate::geoip2;
use crate::reader::validate_metadata_for_reader;
use crate::{MaxMindDbError, Reader, Within, WithinOptions};

const TEST_DATABASE_CONFIGS: &[(usize, usize)] =
    &[(24, 4), (28, 4), (32, 4), (24, 6), (28, 6), (32, 6)];
const TEST_RECORD_SIZES: &[usize] = &[24, 28, 32];
fn init_logger() {
    let _ = env_logger::try_init();
}

fn open_test_data_reader(database: &str) -> Reader<Vec<u8>> {
    Reader::open_readfile(format!("test-data/test-data/{database}"))
        .unwrap_or_else(|e| panic!("failed to open test database '{database}': {e}"))
}

fn collect_networks<S: AsRef<[u8]>>(iter: Within<'_, S>) -> Vec<String> {
    iter.map(|result| {
        result
            .unwrap_or_else(|e| panic!("unexpected iterator error: {e}"))
            .network()
            .unwrap_or_else(|e| panic!("failed to build network from lookup result: {e}"))
            .to_string()
    })
    .collect()
}

#[allow(clippy::float_cmp)]
#[test]
fn test_decoder() {
    init_logger();

    #[allow(non_snake_case)]
    #[derive(Deserialize, Debug, Eq, PartialEq)]
    struct MapXType {
        arrayX: Vec<u32>,
        utf8_stringX: String,
    }

    #[allow(non_snake_case)]
    #[derive(Deserialize, Debug, Eq, PartialEq)]
    struct MapType {
        mapX: MapXType,
    }

    #[derive(Deserialize, Debug)]
    struct TestType<'a> {
        array: Vec<u32>,
        boolean: bool,
        bytes: &'a [u8],
        double: f64,
        float: f32,
        int32: i32,
        map: MapType,
        uint16: u16,
        uint32: u32,
        uint64: u64,
        uint128: u128,
        utf8_string: String,
    }

    let r = open_test_data_reader("MaxMind-DB-test-decoder.mmdb");
    let ip: IpAddr = "1.1.1.0".parse().unwrap();
    let lookup = r.lookup(ip).unwrap();
    assert!(lookup.has_data(), "Expected IP to be found");
    let result: TestType = lookup.decode().unwrap().unwrap();

    assert_eq!(result.array, vec![1_u32, 2_u32, 3_u32]);
    assert!(result.boolean);
    assert_eq!(result.bytes, vec![0_u8, 0_u8, 0_u8, 42_u8]);
    assert_eq!(result.double, 42.123_456);
    assert_eq!(result.float, 1.1);
    assert_eq!(result.int32, -268_435_456);

    assert_eq!(
        result.map,
        MapType {
            mapX: MapXType {
                arrayX: vec![7, 8, 9],
                utf8_stringX: "hello".to_string(),
            },
        }
    );

    assert_eq!(result.uint16, 100);
    assert_eq!(result.uint32, 268_435_456);
    assert_eq!(result.uint64, 1_152_921_504_606_846_976);
    assert_eq!(
        result.uint128,
        1_329_227_995_784_915_872_903_807_060_280_344_576
    );

    assert_eq!(
        result.utf8_string,
        "unicode! \u{262f} - \u{266b}".to_string()
    );
}

#[test]
fn test_pointers_in_metadata() {
    init_logger();

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
    init_logger();

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
    init_logger();

    let r = Reader::open_readfile("file-does-not-exist.mmdb");
    match r {
        Ok(_) => panic!("Received Reader when opening non-existent file"),
        Err(e) => assert!(matches!(e, MaxMindDbError::Io(_))), // Specific message might vary by OS/locale
    }
}

#[test]
fn test_non_database() {
    init_logger();

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
    init_logger();

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
    init_logger();

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
    init_logger();

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
fn test_lookup_city() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-City-Test.mmdb");

    let ip: IpAddr = "89.160.20.112".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let city: geoip2::City = lookup.decode().unwrap().unwrap();

    let iso_code = city.country.iso_code;

    assert_eq!(iso_code, Some("SE"));
}

#[test]
fn test_lookup_country() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-Country-Test.mmdb");

    let ip: IpAddr = "89.160.20.112".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let country: geoip2::Country = lookup.decode().unwrap().unwrap();

    assert_eq!(country.country.iso_code, Some("SE"));
    assert_eq!(country.country.is_in_european_union, Some(true));
}

#[test]
fn test_lookup_connection_type() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-Connection-Type-Test.mmdb");

    let ip: IpAddr = "96.1.20.112".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let connection_type: geoip2::ConnectionType = lookup.decode().unwrap().unwrap();

    assert_eq!(connection_type.connection_type, Some("Cable/DSL"));
}

#[test]
fn test_lookup_annonymous_ip() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-Anonymous-IP-Test.mmdb");

    let ip: IpAddr = "81.2.69.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let anonymous_ip: geoip2::AnonymousIp = lookup.decode().unwrap().unwrap();

    assert_eq!(anonymous_ip.is_anonymous, Some(true));
    assert_eq!(anonymous_ip.is_public_proxy, Some(true));
    assert_eq!(anonymous_ip.is_anonymous_vpn, Some(true));
    assert_eq!(anonymous_ip.is_hosting_provider, Some(true));
    assert_eq!(anonymous_ip.is_tor_exit_node, Some(true))
}

#[test]
fn test_lookup_density_income() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-DensityIncome-Test.mmdb");

    let ip: IpAddr = "5.83.124.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let density_income: geoip2::DensityIncome = lookup.decode().unwrap().unwrap();

    assert_eq!(density_income.average_income, Some(32323));
    assert_eq!(density_income.population_density, Some(1232))
}

#[test]
fn test_lookup_domain() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-Domain-Test.mmdb");

    let ip: IpAddr = "66.92.80.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let domain: geoip2::Domain = lookup.decode().unwrap().unwrap();

    assert_eq!(domain.domain, Some("speakeasy.net"));
}

#[test]
fn test_lookup_isp() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-ISP-Test.mmdb");

    let ip: IpAddr = "12.87.118.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let isp: geoip2::Isp = lookup.decode().unwrap().unwrap();

    assert_eq!(isp.autonomous_system_number, Some(7018));
    assert_eq!(isp.isp, Some("AT&T Services"));
    assert_eq!(isp.organization, Some("AT&T Worldnet Services"));
}

#[test]
fn test_lookup_asn() {
    init_logger();

    let reader = open_test_data_reader("GeoLite2-ASN-Test.mmdb");

    let ip: IpAddr = "1.128.0.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let asn: geoip2::Asn = lookup.decode().unwrap().unwrap();

    assert_eq!(asn.autonomous_system_number, Some(1221));
    assert_eq!(asn.autonomous_system_organization, Some("Telstra Pty Ltd"));
}

#[test]
fn test_lookup_network() {
    init_logger();
    let reader = open_test_data_reader("GeoIP2-City-Test.mmdb");

    // --- IPv4 Check (Known) ---
    let ip: IpAddr = "89.160.20.128".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data(), "Expected Some(City) for known IPv4");
    let network = lookup.network().unwrap();
    assert_eq!(network.prefix(), 25);
    let city: geoip2::City = lookup.decode().unwrap().unwrap();
    assert!(!city.country.is_empty());

    // --- IPv4 Check (Last Host, Known) ---
    let ip_last: IpAddr = "89.160.20.254".parse().unwrap();
    let lookup_last = reader.lookup(ip_last).unwrap();
    assert!(lookup_last.has_data(), "Expected Some(City) for last host");
    assert_eq!(lookup_last.network().unwrap().prefix(), 25); // Should be same network

    // --- IPv6 Check (Not Found in Data) ---
    // This IP might resolve to a node in the tree, but that node might not point to data.
    let ip_v6_not_found: IpAddr = "2c0f:ff00::1".parse().unwrap();
    let lookup_nf = reader.lookup(ip_v6_not_found).unwrap();
    assert!(
        !lookup_nf.has_data(),
        "Expected not found for non-existent IP 2c0f:ff00::1"
    );
    assert_eq!(
        lookup_nf.network().unwrap().prefix(),
        6,
        "Expected valid prefix length for not-found IPv6"
    );

    // --- IPv6 Check (Known Data) ---
    let ip_v6_known: IpAddr = "2001:218:85a3:0:0:8a2e:370:7334".parse().unwrap();
    let lookup_v6 = reader.lookup(ip_v6_known).unwrap();
    assert!(lookup_v6.has_data(), "Expected Some(City) for known IPv6");
    assert_eq!(
        lookup_v6.network().unwrap().prefix(),
        32,
        "Prefix length mismatch for known IPv6"
    );
    let city_v6: geoip2::City = lookup_v6.decode().unwrap().unwrap();
    assert!(!city_v6.country.is_empty());
}

#[test]
fn test_within_city() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-City-Test.mmdb");

    // --- Test iteration over entire DB ("::/0") ---
    let ip_net_all = IpNetwork::V6("::/0".parse().unwrap());
    let mut iter_all: Within<_> = reader.within(ip_net_all, Default::default()).unwrap();

    // Get the first item
    let first_item_result = iter_all.next();
    assert!(
        first_item_result.is_some(),
        "Iterator over ::/0 yielded no items"
    );
    let _first_lookup = first_item_result.unwrap().unwrap();

    // Count the remaining items to check total count
    let mut n = 1; // Start at 1 since we already took the first item
    for item_result in iter_all {
        assert!(item_result.is_ok());
        n += 1;
    }
    assert_eq!(n, 250);

    // --- Test iteration over a specific smaller network ---
    let specific = IpNetwork::V4("81.2.69.0/24".parse().unwrap());
    let mut iter_specific: Within<_> = reader.within(specific, Default::default()).unwrap();

    let expected = vec![
        // In order of iteration:
        IpNetwork::V4("81.2.69.142/31".parse().unwrap()),
        IpNetwork::V4("81.2.69.144/28".parse().unwrap()),
        IpNetwork::V4("81.2.69.160/27".parse().unwrap()),
        IpNetwork::V4("81.2.69.192/28".parse().unwrap()),
    ];

    let mut found_count = 0;
    // Use into_iter() to consume the vector
    for expected_net in expected.into_iter() {
        let item_res = iter_specific.next();
        assert!(
            item_res.is_some(),
            "Expected more items in specific iterator"
        );
        let lookup = item_res.unwrap().unwrap();
        let network = lookup.network().unwrap();
        assert_eq!(
            network, expected_net,
            "Mismatch in specific network iteration"
        );
        // Check associated data for one of them
        if network.prefix() == 31 {
            // 81.2.69.142/31
            let city: geoip2::City = lookup.decode().unwrap().unwrap();
            assert!(!city.city.is_empty());
            assert_eq!(city.city.geoname_id, Some(2643743)); // London
        }
        found_count += 1;
    }
    assert!(
        iter_specific.next().is_none(),
        "Specific iterator should be exhausted after expected items"
    );
    assert_eq!(
        found_count, 4,
        "Expected exactly 4 networks in 81.2.69.0/24"
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
        assert_eq!(metadata.node_count, 163)
    } else {
        assert_eq!(metadata.node_count, 415)
    }

    assert_eq!(metadata.record_size, record_size as u16)
}

#[test]
fn test_metadata_build_time_conversion() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-City-Test.mmdb");

    assert_eq!(
        reader.metadata().build_time().unwrap(),
        UNIX_EPOCH + Duration::from_secs(reader.metadata().build_epoch)
    );
}

#[test]
fn test_metadata_build_time_rejects_uint64_max_epoch() {
    init_logger();

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
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");

    assert_eq!(reader.metadata().record_size, 24);
    assert_eq!(reader.metadata().ip_version, 4);
    assert_eq!(reader.metadata().database_type, "Test");
}

#[test]
fn test_metadata_validation_rejects_hard_invariants() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");
    let metadata = reader.metadata();

    let mut invalid = metadata.clone();
    invalid.binary_format_major_version = 3;
    assert!(matches!(
        validate_metadata_for_reader(&invalid),
        Err(MaxMindDbError::InvalidDatabase { .. })
    ));

    let mut future_minor = metadata.clone();
    future_minor.binary_format_minor_version = u16::MAX;
    validate_metadata_for_reader(&future_minor).unwrap();

    let mut invalid = metadata.clone();
    invalid.ip_version = 5;
    assert!(matches!(
        validate_metadata_for_reader(&invalid),
        Err(MaxMindDbError::InvalidDatabase { .. })
    ));

    let mut invalid = metadata.clone();
    invalid.node_count = 0;
    assert!(matches!(
        validate_metadata_for_reader(&invalid),
        Err(MaxMindDbError::InvalidDatabase { .. })
    ));
}

#[test]
fn test_resolve_data_pointer_rejects_small_pointer() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");
    let err = reader
        .resolve_data_pointer(reader.metadata().node_count as usize)
        .unwrap_err();

    assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
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

#[test]
fn test_json_serialize() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-City-Test.mmdb");

    let ip: IpAddr = "89.160.20.112".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let city: geoip2::City = lookup.decode().unwrap().unwrap();

    let json_value = json!(city);
    let json_string = json_value.to_string();

    let expected_json_str = r#"{"city":{"geoname_id":2694762,"names":{"de":"Linköping","en":"Linköping","fr":"Linköping","ja":"リンシェーピング","zh-CN":"林雪平"}},"continent":{"code":"EU","geoname_id":6255148,"names":{"de":"Europa","en":"Europe","es":"Europa","fr":"Europe","ja":"ヨーロッパ","pt-BR":"Europa","ru":"Европа","zh-CN":"欧洲"}},"country":{"geoname_id":2661886,"is_in_european_union":true,"iso_code":"SE","names":{"de":"Schweden","en":"Sweden","es":"Suecia","fr":"Suède","ja":"スウェーデン王国","pt-BR":"Suécia","ru":"Швеция","zh-CN":"瑞典"}},"location":{"accuracy_radius":76,"latitude":58.4167,"longitude":15.6167,"time_zone":"Europe/Stockholm"},"registered_country":{"geoname_id":2921044,"is_in_european_union":true,"iso_code":"DE","names":{"de":"Deutschland","en":"Germany","es":"Alemania","fr":"Allemagne","ja":"ドイツ連邦共和国","pt-BR":"Alemanha","ru":"Германия","zh-CN":"德国"}},"subdivisions":[{"geoname_id":2685867,"iso_code":"E","names":{"en":"Östergötland County","fr":"Comté d'Östergötland"}}]}"#;
    let expected_value: serde_json::Value = serde_json::from_str(expected_json_str).unwrap();

    assert_eq!(json_value, expected_value);
    assert_eq!(json_string, expected_json_str);
}

// ============================================================================
// Iteration Options Tests
// ============================================================================

/// Test networks() method iterates over entire database
#[test]
fn test_networks() {
    init_logger();

    for (record_size, ip_version) in TEST_DATABASE_CONFIGS {
        let reader = open_test_data_reader(&format!(
            "MaxMind-DB-test-ipv{ip_version}-{record_size}.mmdb"
        ));

        for result in reader.networks(Default::default()).unwrap() {
            let lookup = result.unwrap();
            assert!(
                lookup.has_data(),
                "networks() should only yield found records by default"
            );

            #[derive(Deserialize)]
            struct IpRecord {
                ip: String,
            }
            let record: IpRecord = lookup.decode().unwrap().unwrap();
            let network = lookup.network().unwrap();
            assert_eq!(
                record.ip,
                network.ip().to_string(),
                "record IP should match network IP"
            );
        }
    }
}

/// Test that default options skip aliased networks
#[test]
fn test_default_skips_aliases() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-mixed-24.mmdb");

    // Without IncludeAliasedNetworks, iterating over ::/0 should yield IPv4 networks only once
    let ip_net_all = IpNetwork::V6("::/0".parse().unwrap());

    let expected_without_aliases = vec![
        "1.1.1.1/32",
        "1.1.1.2/31",
        "1.1.1.4/30",
        "1.1.1.8/29",
        "1.1.1.16/28",
        "1.1.1.32/32",
        "::1:ffff:ffff/128",
        "::2:0:0/122",
        "::2:0:40/124",
        "::2:0:50/125",
        "::2:0:58/127",
    ];

    let networks = collect_networks(reader.within(ip_net_all, Default::default()).unwrap());

    assert_eq!(networks, expected_without_aliases);
}

/// Test IncludeAliasedNetworks option
#[test]
fn test_include_aliased_networks() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-mixed-24.mmdb");

    let ip_net_all = IpNetwork::V6("::/0".parse().unwrap());
    let opts = WithinOptions::default().include_aliased_networks();

    // With IncludeAliasedNetworks, we should see IPv4 networks via various IPv6 prefixes
    let expected_with_aliases = vec![
        "1.1.1.1/32",
        "1.1.1.2/31",
        "1.1.1.4/30",
        "1.1.1.8/29",
        "1.1.1.16/28",
        "1.1.1.32/32",
        "::1:ffff:ffff/128",
        "::2:0:0/122",
        "::2:0:40/124",
        "::2:0:50/125",
        "::2:0:58/127",
        "::ffff:1.1.1.1/128",
        "::ffff:1.1.1.2/127",
        "::ffff:1.1.1.4/126",
        "::ffff:1.1.1.8/125",
        "::ffff:1.1.1.16/124",
        "::ffff:1.1.1.32/128",
        "2001:0:101:101::/64",
        "2001:0:101:102::/63",
        "2001:0:101:104::/62",
        "2001:0:101:108::/61",
        "2001:0:101:110::/60",
        "2001:0:101:120::/64",
        "2002:101:101::/48",
        "2002:101:102::/47",
        "2002:101:104::/46",
        "2002:101:108::/45",
        "2002:101:110::/44",
        "2002:101:120::/48",
    ];

    let networks = collect_networks(reader.within(ip_net_all, opts).unwrap());

    assert_eq!(networks, expected_with_aliases);
}

/// Test IncludeNetworksWithoutData option
#[test]
fn test_include_networks_without_data() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-mixed-24.mmdb");

    // Using 1.0.0.0/8 like the Go tests
    let cidr: IpNetwork = "1.0.0.0/8".parse().unwrap();
    let opts = WithinOptions::default().include_networks_without_data();

    let expected = vec![
        "1.0.0.0/16",
        "1.1.0.0/24",
        "1.1.1.0/32",
        "1.1.1.1/32",
        "1.1.1.2/31",
        "1.1.1.4/30",
        "1.1.1.8/29",
        "1.1.1.16/28",
        "1.1.1.32/32",
        "1.1.1.33/32",
        "1.1.1.34/31",
        "1.1.1.36/30",
        "1.1.1.40/29",
        "1.1.1.48/28",
        "1.1.1.64/26",
        "1.1.1.128/25",
        "1.1.2.0/23",
        "1.1.4.0/22",
        "1.1.8.0/21",
        "1.1.16.0/20",
        "1.1.32.0/19",
        "1.1.64.0/18",
        "1.1.128.0/17",
        "1.2.0.0/15",
        "1.4.0.0/14",
        "1.8.0.0/13",
        "1.16.0.0/12",
        "1.32.0.0/11",
        "1.64.0.0/10",
        "1.128.0.0/9",
    ];

    let mut networks: Vec<String> = Vec::new();
    let mut found_count = 0;
    let mut not_found_count = 0;

    for result in reader.within(cidr, opts).unwrap() {
        let lookup = result.unwrap();
        networks.push(lookup.network().unwrap().to_string());
        if lookup.has_data() {
            found_count += 1;
        } else {
            not_found_count += 1;
        }
    }

    assert_eq!(networks, expected);
    assert!(
        not_found_count > 0,
        "Should have some networks without data"
    );
    assert!(found_count > 0, "Should have some networks with data");
}

/// Test SkipEmptyValues option
#[test]
fn test_skip_empty_values() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-Anonymous-IP-Test.mmdb");

    // Count networks without SkipEmptyValues
    let mut count_without_skip = 0;
    let mut empty_count = 0;

    for result in reader.networks(Default::default()).unwrap() {
        let lookup = result.unwrap();
        count_without_skip += 1;

        if lookup.has_data() {
            let data: std::collections::BTreeMap<String, serde_json::Value> =
                lookup.decode().unwrap().unwrap();
            if data.is_empty() {
                empty_count += 1;
            }
        }
    }

    // Count networks with SkipEmptyValues
    let mut count_with_skip = 0;
    let opts = WithinOptions::default().skip_empty_values();

    for result in reader.networks(opts).unwrap() {
        let lookup = result.unwrap();
        count_with_skip += 1;

        if lookup.has_data() {
            let data: std::collections::BTreeMap<String, serde_json::Value> =
                lookup.decode().unwrap().unwrap();
            assert!(
                !data.is_empty(),
                "Should not see empty maps with skip_empty_values"
            );
        }
    }

    // Verify the option works
    assert!(
        empty_count > 0,
        "Test database should have empty values, found {} empty out of {}",
        empty_count,
        count_without_skip
    );
    assert_eq!(
        count_without_skip - empty_count,
        count_with_skip,
        "SkipEmptyValues should skip exactly the empty values"
    );
}

/// Test SkipEmptyValues with other options combined
#[test]
fn test_skip_empty_values_with_other_options() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-Anonymous-IP-Test.mmdb");

    // Test with IncludeNetworksWithoutData - should still skip empty maps
    let opts = WithinOptions::default()
        .include_networks_without_data()
        .skip_empty_values();

    let mut count = 0;
    for result in reader.networks(opts).unwrap() {
        let lookup = result.unwrap();
        count += 1;

        if lookup.has_data() {
            let data: std::collections::BTreeMap<String, serde_json::Value> =
                lookup.decode().unwrap().unwrap();
            assert!(
                !data.is_empty(),
                "Should not see empty maps even with other options"
            );
        }
    }

    assert!(count > 0, "Should have some networks");
}

/// Test various NetworksWithin scenarios matching Go tests
#[test]
fn test_networks_within_scenarios() {
    init_logger();

    struct TestCase {
        network: &'static str,
        database: &'static str,
        expected: Vec<&'static str>,
    }

    let test_cases = vec![
        TestCase {
            network: "0.0.0.0/0",
            database: "ipv4",
            expected: vec![
                "1.1.1.1/32",
                "1.1.1.2/31",
                "1.1.1.4/30",
                "1.1.1.8/29",
                "1.1.1.16/28",
                "1.1.1.32/32",
            ],
        },
        TestCase {
            network: "1.1.1.1/30",
            database: "ipv4",
            expected: vec!["1.1.1.1/32", "1.1.1.2/31"],
        },
        TestCase {
            network: "1.1.1.2/31",
            database: "ipv4",
            expected: vec!["1.1.1.2/31"],
        },
        TestCase {
            network: "1.1.1.1/32",
            database: "ipv4",
            expected: vec!["1.1.1.1/32"],
        },
        TestCase {
            network: "1.1.1.2/32",
            database: "ipv4",
            expected: vec!["1.1.1.2/31"],
        },
        TestCase {
            network: "1.1.1.3/32",
            database: "ipv4",
            expected: vec!["1.1.1.2/31"],
        },
        TestCase {
            network: "1.1.1.19/32",
            database: "ipv4",
            expected: vec!["1.1.1.16/28"],
        },
        TestCase {
            network: "255.255.255.0/24",
            database: "ipv4",
            expected: vec![],
        },
        TestCase {
            network: "1.1.1.1/32",
            database: "mixed",
            expected: vec!["1.1.1.1/32"],
        },
        TestCase {
            network: "255.255.255.0/24",
            database: "mixed",
            expected: vec![],
        },
        TestCase {
            network: "::1:ffff:ffff/128",
            database: "ipv6",
            expected: vec!["::1:ffff:ffff/128"],
        },
        TestCase {
            network: "::/0",
            database: "ipv6",
            expected: vec![
                "::1:ffff:ffff/128",
                "::2:0:0/122",
                "::2:0:40/124",
                "::2:0:50/125",
                "::2:0:58/127",
            ],
        },
        TestCase {
            network: "::2:0:40/123",
            database: "ipv6",
            expected: vec!["::2:0:40/124", "::2:0:50/125", "::2:0:58/127"],
        },
        TestCase {
            network: "0:0:0:0:0:ffff:ffff:ff00/120",
            database: "ipv6",
            expected: vec![],
        },
        TestCase {
            network: "0.0.0.0/0",
            database: "mixed",
            expected: vec![
                "1.1.1.1/32",
                "1.1.1.2/31",
                "1.1.1.4/30",
                "1.1.1.8/29",
                "1.1.1.16/28",
                "1.1.1.32/32",
            ],
        },
        TestCase {
            network: "1.1.1.16/28",
            database: "mixed",
            expected: vec!["1.1.1.16/28"],
        },
        TestCase {
            network: "1.1.1.4/30",
            database: "ipv4",
            expected: vec!["1.1.1.4/30"],
        },
    ];

    for record_size in TEST_RECORD_SIZES {
        for test in &test_cases {
            let reader = open_test_data_reader(&format!(
                "MaxMind-DB-test-{}-{}.mmdb",
                test.database, record_size
            ));

            let cidr: IpNetwork = test.network.parse().unwrap();
            let networks = collect_networks(reader.within(cidr, Default::default()).unwrap());

            let expected: Vec<String> = test.expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                networks, expected,
                "Mismatch for {} in {}-{}: expected {:?}, got {:?}",
                test.network, test.database, record_size, expected, networks
            );
        }
    }
}

/// Test GeoIP database-specific NetworksWithin
#[test]
fn test_geoip_networks_within() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-Country-Test.mmdb");

    let cidr: IpNetwork = "81.2.69.128/26".parse().unwrap();
    let expected = vec!["81.2.69.142/31", "81.2.69.144/28", "81.2.69.160/27"];

    let networks = collect_networks(reader.within(cidr, Default::default()).unwrap());

    assert_eq!(networks, expected);
}

#[test]
fn test_within_rejects_ipv6_cidr_for_ipv4_database() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");

    for cidr in ["::/0", "::ffff:0.0.0.0/96", "2001::/16"] {
        let cidr: IpNetwork = cidr.parse().unwrap();
        let result = reader.within(cidr, Default::default());

        assert!(
            matches!(
                result,
                Err(MaxMindDbError::InvalidInput { ref message })
                    if message == "cannot iterate IPv6 network in IPv4-only database"
            ),
            "Expected InvalidInput for IPv6 CIDR in IPv4 database, got {:?}",
            result
        );
    }
}

#[test]
fn test_within_no_ipv4_search_tree() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-no-ipv4-search-tree.mmdb");

    for cidr in ["::/0", "::/64", "0.0.0.0/0", "200.0.2.1/32"] {
        let cidr: IpNetwork = cidr.parse().unwrap();
        let networks = collect_networks(reader.within(cidr, Default::default()).unwrap());

        assert_eq!(networks, vec!["::/64"], "unexpected networks for {cidr}");
    }
}

/// Test that verify() succeeds on valid databases (matching Go's TestVerifyOnGoodDatabases)
#[test]
fn test_verify_good_databases() {
    init_logger();

    let databases = [
        "GeoIP2-Anonymous-IP-Test.mmdb",
        "GeoIP2-City-Test.mmdb",
        "GeoIP2-Connection-Type-Test.mmdb",
        "GeoIP2-Country-Test.mmdb",
        "GeoIP2-Domain-Test.mmdb",
        "GeoIP2-ISP-Test.mmdb",
        "GeoIP2-Precision-Enterprise-Test.mmdb",
        "MaxMind-DB-no-ipv4-search-tree.mmdb",
        "MaxMind-DB-string-value-entries.mmdb",
        "MaxMind-DB-test-decoder.mmdb",
        "MaxMind-DB-test-ipv4-24.mmdb",
        "MaxMind-DB-test-ipv4-28.mmdb",
        "MaxMind-DB-test-ipv4-32.mmdb",
        "MaxMind-DB-test-ipv6-24.mmdb",
        "MaxMind-DB-test-ipv6-28.mmdb",
        "MaxMind-DB-test-ipv6-32.mmdb",
        "MaxMind-DB-test-metadata-pointers.mmdb",
        "MaxMind-DB-test-mixed-24.mmdb",
        "MaxMind-DB-test-mixed-28.mmdb",
        "MaxMind-DB-test-mixed-32.mmdb",
        "MaxMind-DB-test-nested.mmdb",
    ];

    for database in &databases {
        let reader = open_test_data_reader(database);

        reader
            .verify()
            .unwrap_or_else(|e| panic!("verify() failed for {}: {}", database, e));
    }
}

/// Test that verify() returns errors on broken databases (matching Go's TestVerifyOnBrokenDatabases)
#[test]
fn test_verify_broken_double_format() {
    init_logger();

    let reader = open_test_data_reader("GeoIP2-City-Test-Broken-Double-Format.mmdb");

    let result = reader.verify();
    assert!(
        result.is_err(),
        "Expected verify() to return error for Broken-Double-Format, but it succeeded"
    );
}

#[test]
fn test_verify_broken_pointers() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-broken-pointers-24.mmdb");

    let result = reader.verify();
    assert!(
        matches!(
            result,
            Err(MaxMindDbError::InvalidDatabase { ref message, .. })
                if message == "the MaxMind DB file's data pointer resolves to an invalid location"
        ),
        "Expected specific InvalidDatabase error for broken-pointers, got {:?}",
        result
    );
}

#[test]
fn test_rejects_data_pointer_to_metadata_marker() {
    init_logger();

    let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
    let reader = Reader::open_readfile(source_path).unwrap();
    assert_eq!(reader.metadata().record_size, 24);

    let pointer = reader.metadata().node_count as usize + 16 + reader.data_section_len;
    assert!(pointer <= 0x00ff_ffff);

    let mut bytes = std::fs::read(source_path).unwrap();
    for record in bytes[..6].chunks_exact_mut(3) {
        record[0] = ((pointer >> 16) & 0xff) as u8;
        record[1] = ((pointer >> 8) & 0xff) as u8;
        record[2] = (pointer & 0xff) as u8;
    }

    let reader = Reader::from_source(bytes).unwrap();
    let err = reader.lookup("1.1.1.1".parse().unwrap()).unwrap_err();
    assert!(
        matches!(err, MaxMindDbError::InvalidDatabase { .. }),
        "Expected InvalidDatabase error for marker pointer, got {err:?}"
    );

    let result = reader.verify();
    assert!(
        matches!(result, Err(MaxMindDbError::InvalidDatabase { .. })),
        "Expected InvalidDatabase error for marker pointer during verify, got {result:?}"
    );
}

#[test]
fn test_verify_broken_search_tree() {
    init_logger();

    let reader = open_test_data_reader("MaxMind-DB-test-broken-search-tree-24.mmdb");

    let result = reader.verify();
    assert!(
        matches!(
            result,
            Err(MaxMindDbError::InvalidDatabase { ref message, .. })
                if message.contains("search tree appears to have a cycle or invalid structure")
        ),
        "Expected specific InvalidDatabase error for broken-search-tree, got {:?}",
        result
    );
}

#[test]
fn test_verify_rejects_truncated_scalar_value() {
    init_logger();

    let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
    let reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");
    let lookup = reader.lookup("1.1.1.32".parse().unwrap()).unwrap();
    let data_offset = lookup.offset().expect("expected data offset");
    let mut bytes = std::fs::read(source_path).unwrap();
    let record_start = reader.pointer_base + data_offset;
    let string_value = b"1.1.1.32";
    let relative_value_offset = bytes[record_start..]
        .windows(string_value.len())
        .position(|window| window == string_value)
        .expect("expected terminal string payload in fixture record");
    let string_ctrl_offset = record_start + relative_value_offset - 1;
    assert_eq!(
        bytes[string_ctrl_offset], 0x48,
        "unexpected string control byte in source fixture"
    );

    // Inflate the terminal string from length 8 to length 28 without adding
    // bytes, so verification must catch the truncated payload.
    bytes[string_ctrl_offset] = 0x5c;

    let reader = Reader::from_source(bytes).unwrap();
    let result = reader.verify();
    assert!(
        matches!(result, Err(MaxMindDbError::InvalidDatabase { .. })),
        "Expected InvalidDatabase error for truncated scalar payload, got {:?}",
        result
    );
}

#[test]
fn test_decode_rejects_truncated_ignored_scalar_value() {
    init_logger();

    let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
    let reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");
    let lookup = reader.lookup("1.1.1.32".parse().unwrap()).unwrap();
    let data_offset = lookup.offset().expect("expected data offset");
    let mut bytes = std::fs::read(source_path).unwrap();
    let record_start = reader.pointer_base + data_offset;
    let string_value = b"1.1.1.32";
    let relative_value_offset = bytes[record_start..]
        .windows(string_value.len())
        .position(|window| window == string_value)
        .expect("expected terminal string payload in fixture record");
    let string_ctrl_offset = record_start + relative_value_offset - 1;
    assert_eq!(
        bytes[string_ctrl_offset], 0x48,
        "unexpected string control byte in source fixture"
    );

    // Inflate the terminal string from length 8 to length 28 without adding
    // bytes. Decoding into a struct with no fields forces serde to skip the
    // corrupt value as unknown data.
    bytes[string_ctrl_offset] = 0x5c;

    #[derive(Deserialize, Debug)]
    struct Empty {}

    let reader = Reader::from_source(bytes).unwrap();
    let lookup = reader.lookup("1.1.1.32".parse().unwrap()).unwrap();
    let err = lookup.decode::<Empty>().unwrap_err();

    assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
}

#[test]
fn test_decode_rejects_deep_nesting_in_ignored_values() {
    init_logger();

    let reader =
        Reader::open_readfile("test-data/bad-data/libmaxminddb/libmaxminddb-deep-nesting.mmdb")
            .unwrap();
    let lookup = reader.lookup("1.1.1.1".parse().unwrap()).unwrap();
    let err = lookup.decode::<geoip2::City>().unwrap_err();

    assert!(
        err.to_string()
            .contains("exceeded maximum data structure depth"),
        "unexpected error: {err}"
    );
}

/// Test that size hints are properly returned for sequences and maps
#[test]
fn test_size_hints() {
    use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    init_logger();

    // Wrapper that captures size_hint for sequences
    struct SeqSizeHint {
        hint: Option<usize>,
        values: Vec<u32>,
    }

    impl<'de> Deserialize<'de> for SeqSizeHint {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = SeqSizeHint;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("sequence")
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                    let hint = seq.size_hint();
                    let mut values = Vec::new();
                    while let Some(v) = seq.next_element()? {
                        values.push(v);
                    }
                    Ok(SeqSizeHint { hint, values })
                }
            }
            deserializer.deserialize_seq(V)
        }
    }

    // Wrapper that captures size_hint for maps
    struct MapSizeHint {
        hint: Option<usize>,
        len: usize,
    }

    impl<'de> Deserialize<'de> for MapSizeHint {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = MapSizeHint;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("map")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                    let hint = map.size_hint();
                    let mut len = 0;
                    while map.next_entry::<String, serde::de::IgnoredAny>()?.is_some() {
                        len += 1;
                    }
                    Ok(MapSizeHint { hint, len })
                }
            }
            deserializer.deserialize_map(V)
        }
    }

    #[derive(Deserialize)]
    struct TestType {
        array: SeqSizeHint,
        map: MapSizeHint,
    }

    let r = open_test_data_reader("MaxMind-DB-test-decoder.mmdb");
    let ip: IpAddr = "1.1.1.0".parse().unwrap();
    let lookup = r.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let result: TestType = lookup.decode().unwrap().unwrap();

    // Verify array size hint matches actual length
    assert_eq!(result.array.hint, Some(3));
    assert_eq!(result.array.values, vec![1, 2, 3]);

    // Verify map size hint matches actual entry count
    assert_eq!(result.map.hint, Some(result.map.len));
    assert!(result.map.len > 0, "Map should have entries");
}

/// Test that deserialize_ignored_any efficiently skips values
#[test]
fn test_ignored_any() {
    use serde::de::IgnoredAny;

    init_logger();

    // Struct that only reads some fields, ignoring others via IgnoredAny
    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct PartialRead {
        utf8_string: String,
        // These fields use IgnoredAny to skip decoding
        array: IgnoredAny,
        map: IgnoredAny,
        uint128: IgnoredAny,
    }

    let r = open_test_data_reader("MaxMind-DB-test-decoder.mmdb");
    let ip: IpAddr = "1.1.1.0".parse().unwrap();
    let lookup = r.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let result: PartialRead = lookup.decode().unwrap().unwrap();

    assert_eq!(result.utf8_string, "unicode! ☯ - ♫");
}

/// Test that string values can be deserialized into enums
#[test]
fn test_enum_deserialization() {
    init_logger();

    #[derive(Deserialize, Debug, PartialEq)]
    enum ConnType {
        #[serde(rename = "Cable/DSL")]
        CableDsl,
    }

    #[derive(Deserialize)]
    struct Record {
        connection_type: ConnType,
    }

    let r = open_test_data_reader("GeoIP2-Connection-Type-Test.mmdb");
    let ip: IpAddr = "96.1.20.112".parse().unwrap();
    let lookup = r.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let result: Record = lookup.decode().unwrap().unwrap();

    assert_eq!(result.connection_type, ConnType::CableDsl);
}

/// Test serde flatten attribute with HashMap<String, IgnoredAny>
///
/// Real-world GeoIP2/GeoLite2 databases don't contain u128 values, so
/// `#[serde(flatten)]` works without issues.
#[test]
fn test_serde_flatten() {
    use serde::de::IgnoredAny;

    init_logger();

    #[derive(Deserialize, Debug)]
    struct PartialCountry {
        continent: Continent,
        #[serde(flatten)]
        _rest: std::collections::HashMap<String, IgnoredAny>,
    }

    #[derive(Deserialize, Debug)]
    struct Continent {
        code: String,
    }

    let r = open_test_data_reader("GeoIP2-Country-Test.mmdb");
    let ip: IpAddr = "81.2.69.160".parse().unwrap();
    let lookup = r.lookup(ip).unwrap();
    assert!(lookup.has_data());

    let result: PartialCountry = lookup.decode().unwrap().unwrap();
    assert_eq!(result.continent.code, "EU");
}

#[test]
fn test_network_iteration_rejects_internal_node_cycle() {
    let mut reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");

    // Make both branches of the root node point back to the root. Opening the
    // original database already populated all layout invariants, so this
    // isolates iterator behavior on a corrupt tree without building a fixture.
    reader.buf[..6].fill(0);

    let err = reader
        .networks(Default::default())
        .unwrap()
        .next()
        .expect("cyclic tree should yield an error")
        .unwrap_err();
    assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
    assert!(err.to_string().contains("address bit length"));
}

#[test]
fn test_verify_follows_and_rejects_invalid_data_pointers() {
    let mut reader = open_test_data_reader("MaxMind-DB-test-ipv4-24.mmdb");
    let data_offset = reader
        .lookup("1.1.1.1".parse().unwrap())
        .unwrap()
        .offset()
        .unwrap();
    let record_start = reader.pointer_base + data_offset;

    // Replace the record with a four-byte data pointer to u32::MAX, which is
    // outside this database's data section.
    reader.buf[record_start..record_start + 5].copy_from_slice(&[0x38, 0xff, 0xff, 0xff, 0xff]);

    let err = reader.verify().unwrap_err();
    assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
    assert!(err.to_string().contains("unexpected end of buffer"));
}
