use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;
use serde::Deserialize;
use serde_json::json;

use crate::geoip2;
use crate::{MaxMindDbError, Reader, Within};

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

    let r = Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb");
    if let Err(err) = r {
        panic!("error opening mmdb: {err:?}");
    }
    let r = r.unwrap();
    let ip: IpAddr = FromStr::from_str("1.1.1.0").unwrap();
    let result: TestType = r.lookup(ip).unwrap().unwrap();

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

    let r = Reader::open_readfile("test-data/test-data/MaxMind-DB-test-metadata-pointers.mmdb");
    if let Err(err) = r {
        panic!("error opening mmdb: {err:?}");
    }
    r.unwrap();
}

#[test]
fn test_broken_database() {
    let _ = env_logger::try_init();

    let r = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test-Broken-Double-Format.mmdb")
        .ok()
        .unwrap();
    let ip: IpAddr = FromStr::from_str("2001:220::").unwrap();

    #[derive(Deserialize, Debug)]
    struct TestType {}
    match r.lookup::<TestType>(ip) {
        Err(e) => assert!(matches!(
            e,
            MaxMindDbError::InvalidDatabase(_) // Check variant, message might vary slightly
        )),
        Ok(Some(_)) => panic!("Unexpected success with broken data"),
        Ok(None) => panic!("Got None, expected InvalidDatabase"),
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
            matches!(&e, MaxMindDbError::InvalidDatabase(s) if s == "Could not find MaxMind DB metadata in file."),
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
    use crate::Mmap;
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

    let ip: IpAddr = FromStr::from_str("89.160.20.112").unwrap();
    let city: geoip2::City = reader.lookup(ip).unwrap().unwrap();

    let iso_code = city.country.and_then(|cy| cy.iso_code);

    assert_eq!(iso_code, Some("SE"));
}

#[test]
fn test_lookup_country() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-Country-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("89.160.20.112").unwrap();
    let country: geoip2::Country = reader.lookup(ip).unwrap().unwrap();
    let country = country.country.unwrap();

    assert_eq!(country.iso_code, Some("SE"));
    assert_eq!(country.is_in_european_union, Some(true));
}

#[test]
fn test_lookup_connection_type() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-Connection-Type-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("96.1.20.112").unwrap();
    let connection_type: geoip2::ConnectionType = reader.lookup(ip).unwrap().unwrap();

    assert_eq!(connection_type.connection_type, Some("Cable/DSL"));
}

#[test]
fn test_lookup_annonymous_ip() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-Anonymous-IP-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("81.2.69.123").unwrap();
    let anonymous_ip: geoip2::AnonymousIp = reader.lookup(ip).unwrap().unwrap();

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

    let ip: IpAddr = FromStr::from_str("5.83.124.123").unwrap();
    let density_income: geoip2::DensityIncome = reader.lookup(ip).unwrap().unwrap();

    assert_eq!(density_income.average_income, Some(32323));
    assert_eq!(density_income.population_density, Some(1232))
}

#[test]
fn test_lookup_domain() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-Domain-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("66.92.80.123").unwrap();
    let domain: geoip2::Domain = reader.lookup(ip).unwrap().unwrap();

    assert_eq!(domain.domain, Some("speakeasy.net"));
}

#[test]
fn test_lookup_isp() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-ISP-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("12.87.118.123").unwrap();
    let isp: geoip2::Isp = reader.lookup(ip).unwrap().unwrap();

    assert_eq!(isp.autonomous_system_number, Some(7018));
    assert_eq!(isp.isp, Some("AT&T Services"));
    assert_eq!(isp.organization, Some("AT&T Worldnet Services"));
}

#[test]
fn test_lookup_asn() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoLite2-ASN-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("1.128.0.123").unwrap();
    let asn: geoip2::Asn = reader.lookup(ip).unwrap().unwrap();

    assert_eq!(asn.autonomous_system_number, Some(1221));
    assert_eq!(asn.autonomous_system_organization, Some("Telstra Pty Ltd"));
}

#[test]
fn test_lookup_prefix() {
    let _ = env_logger::try_init();
    let filename = "test-data/test-data/GeoIP2-City-Test.mmdb";
    let reader = Reader::open_readfile(filename).unwrap();

    // --- IPv4 Check (Known) ---
    let ip: IpAddr = "89.160.20.128".parse().unwrap();
    let result_v4 = reader.lookup_prefix::<geoip2::City>(ip);
    assert!(result_v4.is_ok());
    let (city_opt_v4, prefix_len_v4) = result_v4.unwrap();
    assert!(city_opt_v4.is_some(), "Expected Some(City) for known IPv4");
    assert_eq!(prefix_len_v4, 25);
    assert!(city_opt_v4.unwrap().country.is_some());

    // --- IPv4 Check (Last Host, Known) ---
    let ip_last: IpAddr = "89.160.20.254".parse().unwrap();
    let (city_opt_last, last_prefix_len) = reader.lookup_prefix::<geoip2::City>(ip_last).unwrap();
    assert!(city_opt_last.is_some(), "Expected Some(City) for last host");
    assert_eq!(last_prefix_len, 25); // Should be same network

    // --- IPv6 Check (Not Found in Data) ---
    // This IP might resolve to a node in the tree, but that node might not point to data.
    let ip_v6_not_found: IpAddr = "2c0f:ff00::1".parse().unwrap();
    let result_not_found = reader.lookup_prefix::<geoip2::City>(ip_v6_not_found);
    assert!(result_not_found.is_ok());
    let (city_opt_nf, prefix_len_nf) = result_not_found.unwrap();
    assert!(
        city_opt_nf.is_none(),
        "Expected None data for non-existent IP 2c0f:ff00::1"
    );
    assert_eq!(
        prefix_len_nf, 6,
        "Expected valid prefix length for not-found IPv6"
    );

    // --- IPv6 Check (Known Data) ---
    let ip_v6_known: IpAddr = "2001:218:85a3:0:0:8a2e:370:7334".parse().unwrap();
    let result_known_v6 = reader.lookup_prefix::<geoip2::City>(ip_v6_known);
    assert!(result_known_v6.is_ok());
    let (city_opt_v6, prefix_len_v6_known) = result_known_v6.unwrap();
    assert!(city_opt_v6.is_some(), "Expected Some(City) for known IPv6");
    assert_eq!(
        prefix_len_v6_known, 32,
        "Prefix length mismatch for known IPv6"
    );
    assert!(city_opt_v6.unwrap().country.is_some());
}

#[test]
fn test_within_city() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-City-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    // --- Test iteration over entire DB ("::/0") ---
    let ip_net_all = IpNetwork::V6("::/0".parse().unwrap());
    let mut iter_all: Within<geoip2::City, _> = reader.within(ip_net_all).unwrap();

    // Get the first item
    let first_item_result = iter_all.next();
    assert!(
        first_item_result.is_some(),
        "Iterator over ::/0 yielded no items"
    );
    let _first_item = first_item_result.unwrap().unwrap();

    // Count the remaining items to check total count
    let mut n = 1; // Start at 1 since we already took the first item
    for item_result in iter_all {
        assert!(item_result.is_ok());
        n += 1;
    }
    assert_eq!(n, 243);

    // --- Test iteration over a specific smaller network ---
    let specific = IpNetwork::V4("81.2.69.0/24".parse().unwrap());
    let mut iter_specific: Within<geoip2::City, _> = reader.within(specific).unwrap();

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
        let item = item_res.unwrap().unwrap();
        assert_eq!(
            item.ip_net, expected_net,
            "Mismatch in specific network iteration"
        );
        // Check associated data for one of them
        if item.ip_net.prefix() == 31 {
            // 81.2.69.142/31
            assert!(item.info.city.is_some());
            assert_eq!(item.info.city.unwrap().geoname_id, Some(2643743)); // London
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
        let ip: IpAddr = FromStr::from_str(subnet).unwrap();
        let result = reader.lookup::<IpType>(ip);

        assert!(
            result.is_ok(),
            "Lookup failed unexpectedly for {}: {:?}",
            subnet,
            result.err()
        );
        let value_option = result.unwrap();
        assert!(
            value_option.is_some(),
            "Lookup for {} returned None unexpectedly",
            subnet
        );
        let value = value_option.unwrap();

        // The value stored is often the network address, not the specific IP looked up
        // We need to parse the found IP and the subnet IP to check containment or equality.
        // For the specific MaxMind-DB-test-ipv* files, the stored value IS the looked-up IP string.
        assert_eq!(value.ip, *subnet);
    }

    // Test lookups that are expected to return "not found" (Ok(None))
    let no_record = ["1.1.1.33", "255.254.253.123", "89fa::"];

    for &address in &no_record {
        if ip_version == 4 && address == "89fa::" {
            continue; // Skip IPv6 address if testing IPv4 db
        }
        if ip_version == 6 && address != "89fa::" {
            continue; // Skip IPv4 addresses if testing IPv6 db
        }

        let ip: IpAddr = FromStr::from_str(address).unwrap();
        let result = reader.lookup::<IpType>(ip);

        assert!(
            matches!(result, Ok(None)),
            "Expected Ok(None) for address {}, but got {:?}",
            address,
            result
        );
    }
}

#[test]
fn test_json_serialize() {
    let _ = env_logger::try_init();

    let filename = "test-data/test-data/GeoIP2-City-Test.mmdb";

    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("89.160.20.112").unwrap();
    let city: geoip2::City = reader.lookup(ip).unwrap().unwrap();

    let json_value = json!(city);
    let json_string = json_value.to_string();

    let expected_json_str = r#"{"city":{"geoname_id":2694762,"names":{"de":"Linköping","en":"Linköping","fr":"Linköping","ja":"リンシェーピング","zh-CN":"林雪平"}},"continent":{"code":"EU","geoname_id":6255148,"names":{"de":"Europa","en":"Europe","es":"Europa","fr":"Europe","ja":"ヨーロッパ","pt-BR":"Europa","ru":"Европа","zh-CN":"欧洲"}},"country":{"geoname_id":2661886,"is_in_european_union":true,"iso_code":"SE","names":{"de":"Schweden","en":"Sweden","es":"Suecia","fr":"Suède","ja":"スウェーデン王国","pt-BR":"Suécia","ru":"Швеция","zh-CN":"瑞典"}},"location":{"accuracy_radius":76,"latitude":58.4167,"longitude":15.6167,"time_zone":"Europe/Stockholm"},"registered_country":{"geoname_id":2921044,"is_in_european_union":true,"iso_code":"DE","names":{"de":"Deutschland","en":"Germany","es":"Alemania","fr":"Allemagne","ja":"ドイツ連邦共和国","pt-BR":"Alemanha","ru":"Германия","zh-CN":"德国"}},"subdivisions":[{"geoname_id":2685867,"iso_code":"E","names":{"en":"Östergötland County","fr":"Comté d'Östergötland"}}]}"#;
    let expected_value: serde_json::Value = serde_json::from_str(expected_json_str).unwrap();

    assert_eq!(json_value, expected_value);
    assert_eq!(json_string, expected_json_str);
}
