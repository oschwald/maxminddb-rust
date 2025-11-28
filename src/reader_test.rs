use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::Deserialize;
use serde_json::json;

use crate::geoip2;
use crate::{MaxMindDbError, Reader, Within, WithinOptions};

#[allow(clippy::float_cmp)]
#[test]
fn test_decoder() {
    let _ = env_logger::try_init();

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

    let r = Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb")
        .expect("error opening mmdb");
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
    let _ = env_logger::try_init();

    Reader::open_readfile("test-data/test-data/MaxMind-DB-test-metadata-pointers.mmdb")
        .expect("error opening mmdb");
}

#[test]
fn test_broken_database() {
    let _ = env_logger::try_init();

    let r = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test-Broken-Double-Format.mmdb")
        .ok()
        .unwrap();
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
    let _ = env_logger::try_init();

    let r = Reader::open_readfile("file-does-not-exist.mmdb");
    match r {
        Ok(_) => panic!("Received Reader when opening non-existent file"),
        Err(e) => assert!(matches!(e, MaxMindDbError::Io(_))), // Specific message might vary by OS/locale
    }
}

#[test]
fn test_non_database() {
    let _ = env_logger::try_init();

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
fn test_reader() {
    let _ = env_logger::try_init();

    let sizes = [24_usize, 28, 32];
    for record_size in &sizes {
        let versions = [4_usize, 6];
        for ip_version in &versions {
            let filename =
                format!("test-data/test-data/MaxMind-DB-test-ipv{ip_version}-{record_size}.mmdb");
            let reader = Reader::open_readfile(filename).ok().unwrap();

            check_metadata(&reader, *ip_version, *record_size);
            check_ip(&reader, *ip_version);
        }
    }
}

/// Create Reader by explicitly reading the entire file into a buffer.
#[test]
fn test_reader_readfile() {
    let _ = env_logger::try_init();

    let sizes = [24_usize, 28, 32];
    for record_size in &sizes {
        let versions = [4_usize, 6];
        for ip_version in &versions {
            let filename =
                format!("test-data/test-data/MaxMind-DB-test-ipv{ip_version}-{record_size}.mmdb");
            let reader = Reader::open_readfile(filename).ok().unwrap();

            check_metadata(&reader, *ip_version, *record_size);
            check_ip(&reader, *ip_version);
        }
    }
}

#[test]
#[cfg(feature = "mmap")]
fn test_reader_mmap() {
    let _ = env_logger::try_init();

    let sizes = [24usize, 28, 32];
    for record_size in sizes.iter() {
        let versions = [4usize, 6];
        for ip_version in versions.iter() {
            let filename = format!(
                "test-data/test-data/MaxMind-DB-test-ipv{}-{}.mmdb",
                ip_version, record_size
            );
            let reader = Reader::open_mmap(filename).ok().unwrap();

            check_metadata(&reader, *ip_version, *record_size);
            check_ip(&reader, *ip_version);
        }
    }
}

#[test]
fn test_lookup_city() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-City-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = "89.160.20.112".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let city: geoip2::City = lookup.decode().unwrap().unwrap();

    let iso_code = city.country.iso_code;

    assert_eq!(iso_code, Some("SE"));
}

#[test]
fn test_lookup_country() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-Country-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = "89.160.20.112".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let country: geoip2::Country = lookup.decode().unwrap().unwrap();

    assert_eq!(country.country.iso_code, Some("SE"));
    assert_eq!(country.country.is_in_european_union, Some(true));
}

#[test]
fn test_lookup_connection_type() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-Connection-Type-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = "96.1.20.112".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let connection_type: geoip2::ConnectionType = lookup.decode().unwrap().unwrap();

    assert_eq!(connection_type.connection_type, Some("Cable/DSL"));
}

#[test]
fn test_lookup_annonymous_ip() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-Anonymous-IP-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

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
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-DensityIncome-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = "5.83.124.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let density_income: geoip2::DensityIncome = lookup.decode().unwrap().unwrap();

    assert_eq!(density_income.average_income, Some(32323));
    assert_eq!(density_income.population_density, Some(1232))
}

#[test]
fn test_lookup_domain() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-Domain-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = "66.92.80.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let domain: geoip2::Domain = lookup.decode().unwrap().unwrap();

    assert_eq!(domain.domain, Some("speakeasy.net"));
}

#[test]
fn test_lookup_isp() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-ISP-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

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
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoLite2-ASN-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = "1.128.0.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let asn: geoip2::Asn = lookup.decode().unwrap().unwrap();

    assert_eq!(asn.autonomous_system_number, Some(1221));
    assert_eq!(asn.autonomous_system_organization, Some("Telstra Pty Ltd"));
}

#[test]
fn test_lookup_network() {
    let _ = env_logger::try_init();
    let filename = "test-data/test-data/GeoIP2-City-Test.mmdb";
    let reader = Reader::open_readfile(filename).unwrap();

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
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-City-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

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
    assert_eq!(n, 243);

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
    let metadata = &reader.metadata;

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
        assert_eq!(metadata.node_count, 164)
    } else {
        assert_eq!(metadata.node_count, 416)
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

#[test]
fn test_json_serialize() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-City-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

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
    let _ = env_logger::try_init();

    // Test with different record sizes and IP versions
    for record_size in &[24_u32, 28, 32] {
        for ip_version in &[4_u32, 6] {
            let filename =
                format!("test-data/test-data/MaxMind-DB-test-ipv{ip_version}-{record_size}.mmdb");
            let reader = Reader::open_readfile(&filename).unwrap();

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
}

/// Test that default options skip aliased networks
#[test]
fn test_default_skips_aliases() {
    let _ = env_logger::try_init();

    let reader =
        Reader::open_readfile("test-data/test-data/MaxMind-DB-test-mixed-24.mmdb").unwrap();

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

    let mut networks: Vec<String> = Vec::new();
    for result in reader.within(ip_net_all, Default::default()).unwrap() {
        let lookup = result.unwrap();
        networks.push(lookup.network().unwrap().to_string());
    }

    assert_eq!(networks, expected_without_aliases);
}

/// Test IncludeAliasedNetworks option
#[test]
fn test_include_aliased_networks() {
    let _ = env_logger::try_init();

    let reader =
        Reader::open_readfile("test-data/test-data/MaxMind-DB-test-mixed-24.mmdb").unwrap();

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

    let mut networks: Vec<String> = Vec::new();
    for result in reader.within(ip_net_all, opts).unwrap() {
        let lookup = result.unwrap();
        networks.push(lookup.network().unwrap().to_string());
    }

    assert_eq!(networks, expected_with_aliases);
}

/// Test IncludeNetworksWithoutData option
#[test]
fn test_include_networks_without_data() {
    let _ = env_logger::try_init();

    let reader =
        Reader::open_readfile("test-data/test-data/MaxMind-DB-test-mixed-24.mmdb").unwrap();

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
    let _ = env_logger::try_init();

    let reader =
        Reader::open_readfile("test-data/test-data/GeoIP2-Anonymous-IP-Test.mmdb").unwrap();

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
    let _ = env_logger::try_init();

    let reader =
        Reader::open_readfile("test-data/test-data/GeoIP2-Anonymous-IP-Test.mmdb").unwrap();

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
    let _ = env_logger::try_init();

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

    for record_size in &[24_u32, 28, 32] {
        for test in &test_cases {
            let filename = format!(
                "test-data/test-data/MaxMind-DB-test-{}-{}.mmdb",
                test.database, record_size
            );
            let reader = Reader::open_readfile(&filename).unwrap();

            let cidr: IpNetwork = test.network.parse().unwrap();
            let mut networks: Vec<String> = Vec::new();

            for result in reader.within(cidr, Default::default()).unwrap() {
                let lookup = result.unwrap();
                networks.push(lookup.network().unwrap().to_string());
            }

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
    let _ = env_logger::try_init();

    let reader = Reader::open_readfile("test-data/test-data/GeoIP2-Country-Test.mmdb").unwrap();

    let cidr: IpNetwork = "81.2.69.128/26".parse().unwrap();
    let expected = vec!["81.2.69.142/31", "81.2.69.144/28", "81.2.69.160/27"];

    let mut networks: Vec<String> = Vec::new();
    for result in reader.within(cidr, Default::default()).unwrap() {
        let lookup = result.unwrap();
        networks.push(lookup.network().unwrap().to_string());
    }

    assert_eq!(networks, expected);
}

/// Test that verify() succeeds on valid databases (matching Go's TestVerifyOnGoodDatabases)
#[test]
fn test_verify_good_databases() {
    let _ = env_logger::try_init();

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
        "MaxMind-DB-test-mixed-24.mmdb",
        "MaxMind-DB-test-mixed-28.mmdb",
        "MaxMind-DB-test-mixed-32.mmdb",
        "MaxMind-DB-test-nested.mmdb",
    ];

    for database in &databases {
        let path = format!("test-data/test-data/{}", database);
        let reader = Reader::open_readfile(&path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", database, e));

        reader
            .verify()
            .unwrap_or_else(|e| panic!("verify() failed for {}: {}", database, e));
    }
}

/// Test that verify() returns errors on broken databases (matching Go's TestVerifyOnBrokenDatabases)
#[test]
fn test_verify_broken_double_format() {
    let _ = env_logger::try_init();

    let reader =
        Reader::open_readfile("test-data/test-data/GeoIP2-City-Test-Broken-Double-Format.mmdb")
            .unwrap();

    let result = reader.verify();
    assert!(
        result.is_err(),
        "Expected verify() to return error for Broken-Double-Format, but it succeeded"
    );
}

#[test]
fn test_verify_broken_pointers() {
    let _ = env_logger::try_init();

    let reader =
        Reader::open_readfile("test-data/test-data/MaxMind-DB-test-broken-pointers-24.mmdb")
            .unwrap();

    let result = reader.verify();
    assert!(
        result.is_err(),
        "Expected verify() to return error for broken-pointers, but it succeeded"
    );
}

#[test]
fn test_verify_broken_search_tree() {
    let _ = env_logger::try_init();

    let reader =
        Reader::open_readfile("test-data/test-data/MaxMind-DB-test-broken-search-tree-24.mmdb")
            .unwrap();

    let result = reader.verify();
    assert!(
        result.is_err(),
        "Expected verify() to return error for broken-search-tree, but it succeeded"
    );
}

/// Test that size hints are properly returned for sequences and maps
#[test]
fn test_size_hints() {
    use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    let _ = env_logger::try_init();

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

    let r = Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
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

    let _ = env_logger::try_init();

    // Struct that only reads some fields, ignoring others via IgnoredAny
    #[derive(Deserialize, Debug)]
    struct PartialRead {
        utf8_string: String,
        // These fields use IgnoredAny to skip decoding
        array: IgnoredAny,
        map: IgnoredAny,
        uint128: IgnoredAny,
    }

    let r = Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
    let ip: IpAddr = "1.1.1.0".parse().unwrap();
    let lookup = r.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let result: PartialRead = lookup.decode().unwrap().unwrap();

    assert_eq!(result.utf8_string, "unicode! ☯ - ♫");
}

/// Test that string values can be deserialized into enums
#[test]
fn test_enum_deserialization() {
    let _ = env_logger::try_init();

    #[derive(Deserialize, Debug, PartialEq)]
    enum ConnType {
        #[serde(rename = "Cable/DSL")]
        CableDsl,
    }

    #[derive(Deserialize)]
    struct Record {
        connection_type: ConnType,
    }

    let r = Reader::open_readfile("test-data/test-data/GeoIP2-Connection-Type-Test.mmdb").unwrap();
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

    let _ = env_logger::try_init();

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

    let r = Reader::open_readfile("test-data/test-data/GeoIP2-Country-Test.mmdb").unwrap();
    let ip: IpAddr = "81.2.69.160".parse().unwrap();
    let lookup = r.lookup(ip).unwrap();
    assert!(lookup.has_data());

    let result: PartialCountry = lookup.decode().unwrap().unwrap();
    assert_eq!(result.continent.code, "EU");
}
