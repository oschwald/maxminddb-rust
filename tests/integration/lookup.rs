use std::net::IpAddr;

use maxminddb::{geoip2, MaxMindDbError, Reader};

use crate::common::open_test_data_reader;

#[test]
fn test_lookup_city() {
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
    let reader = open_test_data_reader("GeoIP2-Connection-Type-Test.mmdb");

    let ip: IpAddr = "96.1.20.112".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let connection_type: geoip2::ConnectionType = lookup.decode().unwrap().unwrap();

    assert_eq!(connection_type.connection_type, Some("Cable/DSL"));
}

#[test]
fn test_lookup_annonymous_ip() {
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
    let reader = open_test_data_reader("GeoIP2-Domain-Test.mmdb");

    let ip: IpAddr = "66.92.80.123".parse().unwrap();
    let lookup = reader.lookup(ip).unwrap();
    assert!(lookup.has_data());
    let domain: geoip2::Domain = lookup.decode().unwrap().unwrap();

    assert_eq!(domain.domain, Some("speakeasy.net"));
}

#[test]
fn test_lookup_isp() {
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
fn test_lookup_networks_across_databases() {
    use std::collections::HashMap;

    struct TestCase {
        ip: &'static str,
        db_file: &'static str,
        expected_network: &'static str,
        expected_found: bool,
    }

    let test_cases = [
        // IPv4 address in IPv6 database - not found, returns containing network
        TestCase {
            ip: "1.1.1.1",
            db_file: "test-data/test-data/MaxMind-DB-test-ipv6-32.mmdb",
            expected_network: "1.0.0.0/8",
            expected_found: false,
        },
        // IPv6 exact match
        TestCase {
            ip: "::1:ffff:ffff",
            db_file: "test-data/test-data/MaxMind-DB-test-ipv6-24.mmdb",
            expected_network: "::1:ffff:ffff/128",
            expected_found: true,
        },
        // IPv6 network match (not exact)
        TestCase {
            ip: "::2:0:1",
            db_file: "test-data/test-data/MaxMind-DB-test-ipv6-24.mmdb",
            expected_network: "::2:0:0/122",
            expected_found: true,
        },
        // IPv4 exact match
        TestCase {
            ip: "1.1.1.1",
            db_file: "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb",
            expected_network: "1.1.1.1/32",
            expected_found: true,
        },
        // IPv4 network match (not exact)
        TestCase {
            ip: "1.1.1.3",
            db_file: "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb",
            expected_network: "1.1.1.2/31",
            expected_found: true,
        },
        // IPv4 in decoder test database
        TestCase {
            ip: "1.1.1.3",
            db_file: "test-data/test-data/MaxMind-DB-test-decoder.mmdb",
            expected_network: "1.1.1.0/24",
            expected_found: true,
        },
        // IPv4-mapped IPv6 address - preserves IPv6 form
        TestCase {
            ip: "::ffff:1.1.1.128",
            db_file: "test-data/test-data/MaxMind-DB-test-decoder.mmdb",
            expected_network: "::ffff:1.1.1.0/120",
            expected_found: true,
        },
        // IPv4-compatible IPv6 address - uses compressed IPv6 notation
        TestCase {
            ip: "::1.1.1.128",
            db_file: "test-data/test-data/MaxMind-DB-test-decoder.mmdb",
            expected_network: "::101:100/120",
            expected_found: true,
        },
        // No IPv4 search tree - IPv4 address returns ::/64
        TestCase {
            ip: "200.0.2.1",
            db_file: "test-data/test-data/MaxMind-DB-no-ipv4-search-tree.mmdb",
            expected_network: "::/64",
            expected_found: true,
        },
        // No IPv4 search tree - IPv6 address in IPv4 range
        TestCase {
            ip: "::200.0.2.1",
            db_file: "test-data/test-data/MaxMind-DB-no-ipv4-search-tree.mmdb",
            expected_network: "::/64",
            expected_found: true,
        },
        // No IPv4 search tree - IPv6 address at boundary of IPv4 space
        TestCase {
            ip: "0:0:0:0:ffff:ffff:ffff:ffff",
            db_file: "test-data/test-data/MaxMind-DB-no-ipv4-search-tree.mmdb",
            expected_network: "::/64",
            expected_found: true,
        },
        // No IPv4 search tree - high IPv6 address not found
        TestCase {
            ip: "ef00::",
            db_file: "test-data/test-data/MaxMind-DB-no-ipv4-search-tree.mmdb",
            expected_network: "8000::/1",
            expected_found: false,
        },
    ];

    // Cache readers to avoid reopening the same file multiple times
    let mut readers: HashMap<&str, Reader<Vec<u8>>> = HashMap::new();

    for test in &test_cases {
        let reader = readers
            .entry(test.db_file)
            .or_insert_with(|| Reader::open_readfile(test.db_file).unwrap());

        let ip: IpAddr = test.ip.parse().unwrap();
        let result = reader.lookup(ip).unwrap();

        assert_eq!(
            result.has_data(),
            test.expected_found,
            "IP {} in {}: expected has_data={}, got has_data={}",
            test.ip,
            test.db_file,
            test.expected_found,
            result.has_data()
        );

        let network = result.network().unwrap();
        assert_eq!(
            network.to_string(),
            test.expected_network,
            "IP {} in {}: expected network {}, got {}",
            test.ip,
            test.db_file,
            test.expected_network,
            network
        );
    }
}

#[test]
fn test_lookup_with_geoip_data() {
    let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let ip: IpAddr = "89.160.20.128".parse().unwrap();

    let result = reader.lookup(ip).unwrap();
    assert!(result.has_data(), "lookup should find known IP");

    // Decode the data
    let city: geoip2::City = result.decode().unwrap().unwrap();
    assert!(!city.city.is_empty(), "Expected city data");

    // Check full network (not just prefix)
    let network = result.network().unwrap();
    assert_eq!(
        network.to_string(),
        "89.160.20.128/25",
        "Expected network 89.160.20.128/25"
    );

    // Check offset is available for caching
    assert!(
        result.offset().is_some(),
        "Expected offset to be Some for found IP"
    );
}

#[test]
fn test_lookup_offset_is_stable_for_shared_record() {
    let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();

    let first = reader.lookup("89.160.20.128".parse().unwrap()).unwrap();
    let second = reader.lookup("89.160.20.129".parse().unwrap()).unwrap();

    assert!(first.has_data());
    assert!(second.has_data());
    assert_eq!(first.network().unwrap(), second.network().unwrap());
    assert_eq!(
        first.offset(),
        second.offset(),
        "IPs in the same record should share a cacheable offset"
    );
}

#[test]
fn test_ipv6_in_ipv4_database() {
    let reader = Reader::open_readfile("test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb").unwrap();
    let ip: IpAddr = "2001::".parse().unwrap();

    let result = reader.lookup(ip);
    match result {
        Err(MaxMindDbError::InvalidInput { message }) => {
            assert!(
                message.contains("IPv6") && message.contains("IPv4"),
                "Expected error message about IPv6 in IPv4 database, got: {}",
                message
            );
        }
        Err(e) => panic!(
            "Expected InvalidInput error for IPv6 in IPv4 database, got: {:?}",
            e
        ),
        Ok(_) => panic!("Expected error for IPv6 lookup in IPv4-only database"),
    }
}
