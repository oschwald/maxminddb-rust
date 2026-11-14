use ipnetwork::IpNetwork;
use serde::Deserialize;

use maxminddb::{geoip2, MaxMindDbError, Reader, Within, WithinOptions};

use crate::common::{open_test_data_reader, TEST_DATABASE_CONFIGS, TEST_RECORD_SIZES};

#[test]
fn test_within_city() {
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

// ============================================================================
// Iteration Options Tests
// ============================================================================

/// Test networks() method iterates over entire database
#[test]
fn test_networks() {
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

#[test]
fn test_iteration_preserves_shared_ipv6_data_records() {
    check_shared_ipv6_terminal(true);
}

#[test]
fn test_iteration_preserves_shared_ipv6_no_data_terminals() {
    check_shared_ipv6_terminal(false);
}

#[test]
fn test_ipv6_root_cycle_is_not_filtered_as_an_alias() {
    let mut bytes = shared_ipv6_terminal_database(true);
    bytes[..6].fill(0);
    let reader = Reader::from_source(bytes).unwrap();

    for options in [
        WithinOptions::default(),
        WithinOptions::default().include_aliased_networks(),
    ] {
        for mut iter in [
            reader.networks(options).unwrap(),
            reader.within("::/0".parse().unwrap(), options).unwrap(),
        ] {
            let err = iter.next().unwrap().unwrap_err();
            assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
            assert!(err.to_string().contains("address bit length"));
        }
    }
    assert!(matches!(
        reader.verify(),
        Err(MaxMindDbError::InvalidDatabase { .. })
    ));
}

/// Test that default options skip aliased networks
#[test]
fn test_default_skips_aliases() {
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
    assert_eq!(
        collect_networks(reader.networks(Default::default()).unwrap()),
        expected_without_aliases
    );
    assert!(reader
        .within("::ffff:0:0/96".parse().unwrap(), Default::default())
        .unwrap()
        .next()
        .is_none());
}

/// Test IncludeAliasedNetworks option
#[test]
fn test_include_aliased_networks() {
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
    assert_eq!(
        collect_networks(reader.networks(opts).unwrap()),
        expected_with_aliases
    );
    assert_eq!(
        collect_networks(
            reader
                .within("::ffff:0:0/96".parse().unwrap(), opts)
                .unwrap()
        ),
        vec![
            "::ffff:1.1.1.1/128",
            "::ffff:1.1.1.2/127",
            "::ffff:1.1.1.4/126",
            "::ffff:1.1.1.8/125",
            "::ffff:1.1.1.16/124",
            "::ffff:1.1.1.32/128",
        ]
    );
}

/// Test IncludeNetworksWithoutData option
#[test]
fn test_include_networks_without_data() {
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
    let reader = open_test_data_reader("GeoIP2-Country-Test.mmdb");

    let cidr: IpNetwork = "81.2.69.128/26".parse().unwrap();
    let expected = vec!["81.2.69.142/31", "81.2.69.144/28", "81.2.69.160/27"];

    let networks = collect_networks(reader.within(cidr, Default::default()).unwrap());

    assert_eq!(networks, expected);
}

#[test]
fn test_within_rejects_ipv6_cidr_for_ipv4_database() {
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
    let reader = open_test_data_reader("MaxMind-DB-no-ipv4-search-tree.mmdb");

    for cidr in ["::/0", "::/64", "0.0.0.0/0", "200.0.2.1/32"] {
        let cidr: IpNetwork = cidr.parse().unwrap();
        let networks = collect_networks(reader.within(cidr, Default::default()).unwrap());

        assert_eq!(networks, vec!["::/64"], "unexpected networks for {cidr}");
    }
}

fn check_shared_ipv6_terminal(has_data: bool) {
    let reader = Reader::from_source(shared_ipv6_terminal_database(has_data)).unwrap();
    reader.verify().unwrap();
    let value = if has_data { Some("X".to_owned()) } else { None };

    for (address, network) in [("::", "::/1"), ("8000::", "8000::/1")] {
        let lookup = reader.lookup(address.parse().unwrap()).unwrap();
        assert_eq!(lookup.network().unwrap(), network.parse().unwrap());
        assert_eq!(lookup.has_data(), has_data);
        assert_eq!(lookup.decode::<String>().unwrap(), value);
    }

    let collect = |iter: Within<'_, Vec<u8>>| {
        iter.map(|result| {
            let lookup = result.unwrap();
            assert_eq!(lookup.has_data(), has_data);
            assert_eq!(lookup.decode::<String>().unwrap(), value);
            lookup.network().unwrap().to_string()
        })
        .collect::<Vec<_>>()
    };

    for include_aliases in [false, true] {
        for include_no_data in [false, true] {
            let mut options = WithinOptions::default();
            if include_aliases {
                options = options.include_aliased_networks();
            }
            if include_no_data {
                options = options.include_networks_without_data();
            }
            let expected = if has_data || include_no_data {
                vec!["::/1", "8000::/1"]
            } else {
                vec![]
            };
            assert_eq!(collect(reader.networks(options).unwrap()), expected);

            for (cidr, containing_networks) in [
                ("::/0", vec!["::/1", "8000::/1"]),
                ("::/1", vec!["::/1"]),
                ("::1/128", vec!["::/1"]),
                ("8000::/1", vec!["8000::/1"]),
                ("9000::/16", vec!["8000::/1"]),
            ] {
                let expected = if has_data || include_no_data {
                    containing_networks
                } else {
                    vec![]
                };
                assert_eq!(
                    collect(reader.within(cidr.parse().unwrap(), options).unwrap()),
                    expected,
                    "within {cidr}, options {options:?}"
                );
            }
        }
    }
}

fn shared_ipv6_terminal_database(has_data: bool) -> Vec<u8> {
    fn string(bytes: &mut Vec<u8>, value: &str) {
        assert!(value.len() < 29, "test strings use a one-byte header");
        bytes.push(0x40 | value.len() as u8);
        bytes.extend_from_slice(value.as_bytes());
    }

    // One 24-bit node. Both /1 networks share either the first data record
    // (node_count + the 16-byte separator) or the node_count no-data sentinel.
    let terminal = if has_data { 17 } else { 1 };
    let mut bytes = vec![0, 0, terminal, 0, 0, terminal];
    bytes.extend_from_slice(&[0; 16]);
    if has_data {
        string(&mut bytes, "X");
    }
    bytes.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    bytes.push(0xe9); // Metadata map with nine fields.
    for (key, encoded_value) in [
        ("binary_format_major_version", &[0xa1, 2][..]), // uint16
        ("binary_format_minor_version", &[0xa1, 0]),
        ("build_epoch", &[0x01, 0x02, 1]), // uint64
        ("ip_version", &[0xa1, 6]),
        ("node_count", &[0xc1, 1]), // uint32
        ("record_size", &[0xa1, 24]),
    ] {
        string(&mut bytes, key);
        bytes.extend_from_slice(encoded_value);
    }
    string(&mut bytes, "database_type");
    string(&mut bytes, "shared-terminals");
    string(&mut bytes, "description");
    bytes.push(0xe1); // Map with one field.
    string(&mut bytes, "en");
    string(&mut bytes, "shared IPv6 terminals");
    string(&mut bytes, "languages");
    bytes.extend_from_slice(&[0x01, 0x04]); // Array with one string.
    string(&mut bytes, "en");
    bytes
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
