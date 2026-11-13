use std::net::IpAddr;

use serde::Deserialize;
use serde_json::json;

use maxminddb::{geoip2, MaxMindDbError, PathElement, Reader};

use crate::common::open_test_data_reader;

#[allow(clippy::float_cmp)]
#[test]
fn test_decoder() {
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
fn test_json_serialize() {
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

#[test]
fn test_decode_rejects_deep_nesting_in_ignored_values() {
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
fn test_pointer_fan_out_is_rejected() {
    // A data section of nested arrays, each holding two pointers to the node
    // below, would cost 2**depth decode operations. The decoder bounds the
    // number of values it decodes for a single record and rejects decoding the
    // record.
    let reader = open_test_data_reader("MaxMind-DB-test-pointer-decoder-dos.mmdb");
    let ip = "1.2.3.4".parse().unwrap();
    let result: Result<Option<serde_json::Value>, _> = reader.lookup(ip).unwrap().decode();
    match result {
        Ok(_) => panic!("expected the fan-out record decode to be rejected"),
        Err(e) => assert!(
            matches!(&e, MaxMindDbError::ResourceLimit { message, .. }
                if message.contains("maximum number of data structure values")),
            "unexpected error: {e}"
        ),
    }
}

#[test]
fn test_payload_amplification_is_rejected() {
    // Each bytes fixture aims many pointers at one large value. `OwnedBytes`
    // enters through deserialize_any before copying, so materializing the
    // pointed-to bytes must trip the dynamic payload budget well before the
    // value-count budget.
    for database in [
        "MaxMind-DB-test-payload-amplification-dos.mmdb",
        "MaxMind-DB-test-payload-amplification-dos-worst-case.mmdb",
    ] {
        let reader = open_test_data_reader(database);
        let ip = "1.2.3.4".parse().unwrap();
        let result: Result<Option<Vec<OwnedBytes>>, _> = reader.lookup(ip).unwrap().decode();
        assert!(
            matches!(&result, Err(MaxMindDbError::ResourceLimit { message, .. })
                if message.contains("maximum size of data structure string and bytes")),
            "unexpected result for {database}: {result:?}"
        );
    }

    // The UTF-8 string variant also trips the budget when materialized into an
    // owned dynamic value, the shape a real consumer copies into.
    let reader = open_test_data_reader("MaxMind-DB-test-payload-amplification-dos-string.mmdb");
    let ip = "1.2.3.4".parse().unwrap();
    let result: Result<Option<serde_json::Value>, _> = reader.lookup(ip).unwrap().decode();
    assert!(
        matches!(&result, Err(MaxMindDbError::ResourceLimit { message, .. })
            if message.contains("maximum size of data structure string and bytes")),
        "unexpected result for string fixture into Value: {result:?}"
    );

    // Concrete collection decoding enters through deserialize_seq rather than
    // deserialize_any and receives the same aggregate payload protection.
    let result: Result<Option<Vec<String>>, _> = reader.lookup(ip).unwrap().decode();
    assert!(
        matches!(&result, Err(MaxMindDbError::ResourceLimit { message, .. })
            if message.contains("maximum size of data structure string and bytes")),
        "unexpected result for string fixture into Vec<String>: {result:?}"
    );

    // A normal record still decodes into a generic value.
    let reader = open_test_data_reader("GeoIP2-City-Test.mmdb");
    let ip = "89.160.20.128".parse().unwrap();
    let value: Option<serde_json::Value> = reader
        .lookup(ip)
        .unwrap()
        .decode()
        .expect("normal record should decode");
    assert!(value.is_some(), "expected a record for the test address");
}

#[test]
fn test_decoder_resource_limit_boundaries() {
    let ip = "1.2.3.4".parse().unwrap();

    for database in [
        "MaxMind-DB-test-decoder-value-limit.mmdb",
        "MaxMind-DB-test-decoder-value-limit-pointer-heavy.mmdb",
    ] {
        let reader = open_test_data_reader(database);
        let result: Result<Option<serde_json::Value>, _> = reader.lookup(ip).unwrap().decode();
        assert!(
            result.is_ok(),
            "expected {database} to be accepted: {result:?}"
        );
    }

    let reader = open_test_data_reader("MaxMind-DB-test-decoder-value-limit-over.mmdb");
    let lookup = reader.lookup(ip).unwrap();
    let result: Result<Option<serde_json::Value>, _> = lookup.decode();
    assert!(
        matches!(&result, Err(MaxMindDbError::ResourceLimit { message, .. })
            if message.contains("maximum number of data structure values")),
        "unexpected result above the value limit: {result:?}"
    );

    let path_result: Result<Option<serde_json::Value>, _> = lookup.decode_path(&[]);
    assert!(
        matches!(&path_result, Err(MaxMindDbError::ResourceLimit { message, .. })
            if message.contains("maximum number of data structure values")),
        "unexpected decode_path result above the value limit: {path_result:?}"
    );

    let reader = open_test_data_reader("MaxMind-DB-test-decoder-payload-limit.mmdb");
    let result: Result<Option<Vec<OwnedBytes>>, _> = reader.lookup(ip).unwrap().decode();
    let values = result
        .expect("expected exact payload limit to be accepted")
        .expect("expected a record at the test address");
    assert_eq!(
        values.iter().map(|value| value.0.len()).sum::<usize>(),
        2 << 20
    );

    let reader = open_test_data_reader("MaxMind-DB-test-decoder-payload-limit-over.mmdb");
    let result: Result<Option<Vec<OwnedBytes>>, _> = reader.lookup(ip).unwrap().decode();
    assert!(
        matches!(&result, Err(MaxMindDbError::ResourceLimit { message, .. })
            if message.contains("maximum size of data structure string and bytes")),
        "unexpected result above the payload limit: {result:?}"
    );
}

#[test]
fn test_decode_path_navigation_and_value_share_payload_budget() {
    let reader = open_test_data_reader("MaxMind-DB-test-decode-path-shared-budget.mmdb");
    let lookup = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
    let err = lookup
        .decode_path::<String>(&[PathElement::Key("target")])
        .unwrap_err();

    assert!(
        matches!(
            &err,
            MaxMindDbError::ResourceLimit {
                message,
                path: Some(path),
                ..
            } if message.contains("maximum size of data structure string and bytes")
                && path == "/target"
        ),
        "unexpected cumulative decode_path result: {err}"
    );
}

#[test]
fn test_decode_path() {
    let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let ip: IpAddr = "89.160.20.128".parse().unwrap();

    let result = reader.lookup(ip).unwrap();

    // Navigate to country.iso_code
    let iso_code: Option<String> = result
        .decode_path(&[PathElement::Key("country"), PathElement::Key("iso_code")])
        .unwrap();
    assert_eq!(iso_code, Some("SE".to_owned()));

    // Navigate to non-existent path
    let missing: Option<String> = result
        .decode_path(&[PathElement::Key("nonexistent")])
        .unwrap();
    assert!(missing.is_none());
}

#[test]
fn test_decode_path_on_not_found_lookup() {
    let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let ip: IpAddr = "2c0f:ff00::1".parse().unwrap();

    let result = reader.lookup(ip).unwrap();

    assert!(!result.has_data());
    assert!(result.offset().is_none());
    assert!(result.decode::<geoip2::City>().unwrap().is_none());

    let country_code: Option<String> = result
        .decode_path(&[PathElement::Key("country"), PathElement::Key("iso_code")])
        .unwrap();
    assert!(country_code.is_none());
}

#[test]
fn test_decode_path_comprehensive() {
    let reader = Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
    let ip: IpAddr = "::1.1.1.0".parse().unwrap();

    let result = reader.lookup(ip).unwrap();
    assert!(result.has_data());

    // Test simple path: uint16
    let u16_val: Option<u16> = result.decode_path(&[PathElement::Key("uint16")]).unwrap();
    assert_eq!(u16_val, Some(100));

    // Test array access: first element
    let arr_first: Option<u32> = result
        .decode_path(&[PathElement::Key("array"), PathElement::Index(0)])
        .unwrap();
    assert_eq!(arr_first, Some(1));

    // Test array access: last element (index 2)
    let arr_last: Option<u32> = result
        .decode_path(&[PathElement::Key("array"), PathElement::Index(2)])
        .unwrap();
    assert_eq!(arr_last, Some(3));

    // Test array access: out of bounds (index 3) returns None
    let arr_oob: Option<u32> = result
        .decode_path(&[PathElement::Key("array"), PathElement::Index(3)])
        .unwrap();
    assert!(arr_oob.is_none());

    // Test IndexFromEnd: 0 means last element
    let arr_last: Option<u32> = result
        .decode_path(&[PathElement::Key("array"), PathElement::IndexFromEnd(0)])
        .unwrap();
    assert_eq!(arr_last, Some(3));

    // Test IndexFromEnd: 2 means first element (array has 3 elements)
    let arr_first: Option<u32> = result
        .decode_path(&[PathElement::Key("array"), PathElement::IndexFromEnd(2)])
        .unwrap();
    assert_eq!(arr_first, Some(1));

    // Test nested path: map.mapX.arrayX[1]
    let nested: Option<u32> = result
        .decode_path(&[
            PathElement::Key("map"),
            PathElement::Key("mapX"),
            PathElement::Key("arrayX"),
            PathElement::Index(1),
        ])
        .unwrap();
    assert_eq!(nested, Some(8));

    // Test non-existent key returns None
    let missing: Option<u32> = result
        .decode_path(&[PathElement::Key("does-not-exist"), PathElement::Index(1)])
        .unwrap();
    assert!(missing.is_none());

    // Test utf8_string path
    let utf8: Option<String> = result
        .decode_path(&[PathElement::Key("utf8_string")])
        .unwrap();
    assert_eq!(utf8, Some("unicode! ☯ - ♫".to_owned()));
}

#[derive(Debug)]
struct OwnedBytes(Vec<u8>);

impl<'de> Deserialize<'de> for OwnedBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct OwnedBytesVisitor;

        impl<'de> serde::de::Visitor<'de> for OwnedBytesVisitor {
            type Value = OwnedBytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bytes value")
            }

            fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E> {
                Ok(OwnedBytes(value.to_vec()))
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(OwnedBytes(value.to_vec()))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                Ok(OwnedBytes(value))
            }
        }

        // Enter through `deserialize_any`, which is the dynamically shaped
        // boundary protected by the decoder's expansion budget.
        deserializer.deserialize_any(OwnedBytesVisitor)
    }
}
