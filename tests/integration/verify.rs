use maxminddb::MaxMindDbError;

use crate::common::open_test_data_reader;

/// Test that verify() succeeds on valid databases (matching Go's TestVerifyOnGoodDatabases)
#[test]
fn test_verify_good_databases() {
    let databases = [
        "GeoIP2-Anonymous-IP-Test.mmdb",
        "GeoIP2-City-Test.mmdb",
        "GeoIP2-Connection-Type-Test.mmdb",
        "GeoIP2-Country-Test.mmdb",
        "GeoIP2-Domain-Test.mmdb",
        "GeoIP2-ISP-Test.mmdb",
        "GeoIP2-Enterprise-Test.mmdb",
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
    let reader = open_test_data_reader("GeoIP2-City-Test-Broken-Double-Format.mmdb");

    let result = reader.verify();
    assert!(
        result.is_err(),
        "Expected verify() to return error for Broken-Double-Format, but it succeeded"
    );
}

#[test]
fn test_verify_broken_pointers() {
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
fn test_verify_broken_search_tree() {
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
