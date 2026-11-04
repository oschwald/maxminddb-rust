use maxminddb::{path, MaxMindDbError, Reader};
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
struct Wrapped<T>(T);

fn decoder_fixture() -> Reader<Vec<u8>> {
    Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap()
}

#[test]
fn derived_newtypes_decode_numeric_paths() {
    let reader = decoder_fixture();
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    assert_eq!(
        lookup
            .decode_path::<Wrapped<u16>>(&path!["uint16"])
            .unwrap(),
        Some(Wrapped(100))
    );
    assert_eq!(
        lookup
            .decode_path::<Wrapped<Wrapped<u32>>>(&path!["uint32"])
            .unwrap(),
        Some(Wrapped(Wrapped(268_435_456)))
    );
    assert_eq!(
        lookup.decode_path::<Wrapped<i32>>(&path!["int32"]).unwrap(),
        Some(Wrapped(-268_435_456))
    );
}

#[test]
fn derived_newtypes_decode_borrowed_and_owned_string_paths() {
    let reader = decoder_fixture();
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    let plain = lookup
        .decode_path::<&str>(&path!["utf8_string"])
        .unwrap()
        .unwrap();
    let borrowed = lookup
        .decode_path::<Wrapped<Wrapped<&str>>>(&path!["utf8_string"])
        .unwrap()
        .unwrap();
    assert_eq!(borrowed, Wrapped(Wrapped("unicode! ☯ - ♫")));
    assert_eq!(borrowed.0 .0.as_ptr(), plain.as_ptr());
    assert_eq!(
        lookup
            .decode_path::<Wrapped<String>>(&path!["utf8_string"])
            .unwrap(),
        Some(Wrapped(plain.to_owned()))
    );
}

#[test]
fn derived_newtypes_decode_records_and_container_elements() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Record<'a> {
        uint32: Wrapped<u32>,
        #[serde(borrow)]
        utf8_string: Wrapped<&'a str>,
        array: Vec<Wrapped<u32>>,
    }

    let reader = decoder_fixture();
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    let expected = Wrapped(Wrapped(Record {
        uint32: Wrapped(268_435_456),
        utf8_string: Wrapped("unicode! ☯ - ♫"),
        array: vec![Wrapped(1), Wrapped(2), Wrapped(3)],
    }));
    assert_eq!(
        lookup.decode::<Wrapped<Wrapped<Record<'_>>>>().unwrap(),
        Some(expected)
    );
    assert_eq!(
        lookup
            .decode_path::<Wrapped<Wrapped<Record<'_>>>>(&[])
            .unwrap(),
        lookup.decode::<Wrapped<Wrapped<Record<'_>>>>().unwrap()
    );
}

// Retain the fixture's search tree and metadata, but replace its data section.
// Both root children point to offset zero in the replacement data.
fn reader_with_data(data: &[u8]) -> Reader<Vec<u8>> {
    let source = std::fs::read("test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb").unwrap();
    let original = Reader::from_source(&source).unwrap();
    let metadata = original.metadata();
    assert_eq!(metadata.record_size, 24);
    let data_start = metadata.node_count as usize * 6 + 16;
    let marker = b"\xab\xcd\xefMaxMind.com";
    let metadata_marker = source
        .windows(marker.len())
        .rposition(|bytes| bytes == marker)
        .unwrap();
    let mut bytes = source[..data_start].to_vec();
    let pointer = (metadata.node_count as u32 + 16).to_be_bytes();
    bytes[..3].copy_from_slice(&pointer[1..]);
    bytes[3..6].copy_from_slice(&pointer[1..]);
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&source[metadata_marker..]);
    Reader::from_source(bytes).unwrap()
}

#[test]
fn derived_newtypes_follow_numeric_and_record_pointers() {
    let reader = reader_with_data(&[0x20, 0x02, 0xc1, 42]); // pointer to uint32
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    assert_eq!(
        lookup.decode::<Wrapped<Wrapped<u32>>>().unwrap(),
        Some(Wrapped(Wrapped(42)))
    );
    assert_eq!(
        lookup.decode_path::<Wrapped<u32>>(&[]).unwrap(),
        Some(Wrapped(42))
    );

    #[derive(Debug, Deserialize, PartialEq)]
    struct Record {
        n: Wrapped<u32>,
    }

    let reader = reader_with_data(&[
        0x20, 0x02, // pointer to map
        0xe1, 0x41, b'n', // map with key "n"
        0x20, 0x07, // pointer to uint32
        0xc1, 42,
    ]);
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    assert_eq!(
        lookup.decode::<Wrapped<Record>>().unwrap(),
        Some(Wrapped(Record { n: Wrapped(42) }))
    );
    assert_eq!(
        lookup.decode_path::<Wrapped<u32>>(&path!["n"]).unwrap(),
        Some(Wrapped(42))
    );
}

#[test]
fn derived_newtypes_restore_pointer_continuations_in_arrays() {
    let reader = reader_with_data(&[
        0x02, 0x04, // array with two elements
        0x20, 0x06, // pointer to "hello"
        0x41, b'z', // inline continuation
        0x45, b'h', b'e', b'l', b'l', b'o',
    ]);
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    assert_eq!(
        lookup.decode::<Wrapped<Vec<Wrapped<&str>>>>().unwrap(),
        Some(Wrapped(vec![Wrapped("hello"), Wrapped("z")]))
    );
    assert_eq!(
        lookup.decode::<Wrapped<Vec<Wrapped<String>>>>().unwrap(),
        Some(Wrapped(vec![
            Wrapped("hello".to_owned()),
            Wrapped("z".to_owned())
        ]))
    );
    let plain = lookup.decode_path::<&str>(&path![0]).unwrap().unwrap();
    let borrowed = lookup
        .decode_path::<Wrapped<&str>>(&path![0])
        .unwrap()
        .unwrap();
    assert_eq!(borrowed.0, "hello");
    assert_eq!(borrowed.0.as_ptr(), plain.as_ptr());
    assert_eq!(
        lookup.decode_path::<Wrapped<String>>(&path![0]).unwrap(),
        Some(Wrapped("hello".to_owned()))
    );
}

#[test]
fn derived_newtypes_preserve_resource_limits() {
    for fixture in [
        "MaxMind-DB-test-decoder-value-limit-over.mmdb",
        "MaxMind-DB-test-pointer-decoder-dos.mmdb",
        "MaxMind-DB-test-payload-amplification-dos-string.mmdb",
    ] {
        let reader = Reader::open_readfile(format!("test-data/test-data/{fixture}")).unwrap();
        let lookup = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
        assert!(lookup.has_data(), "missing record in {fixture}");
        assert!(matches!(
            lookup.decode::<Wrapped<serde_json::Value>>(),
            Err(MaxMindDbError::ResourceLimit { .. })
        ));
        assert!(matches!(
            lookup.decode_path::<Wrapped<serde_json::Value>>(&[]),
            Err(MaxMindDbError::ResourceLimit { .. })
        ));
    }
}

#[test]
fn derived_newtypes_preserve_standalone_payload_limit() {
    let size = 2 * 1024 * 1024 + 1;
    let encoded_size = u32::try_from(size - 65_821).unwrap();
    let mut data = vec![0x5f]; // string with a three-byte extended size
    data.extend_from_slice(&encoded_size.to_be_bytes()[1..]);
    data.resize(data.len() + size, b'a');
    let reader = reader_with_data(&data);
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    assert!(matches!(
        lookup.decode::<Wrapped<&str>>(),
        Err(MaxMindDbError::ResourceLimit { .. })
    ));
    assert!(matches!(
        lookup.decode_path::<Wrapped<String>>(&[]),
        Err(MaxMindDbError::ResourceLimit { .. })
    ));
}

#[test]
fn derived_newtypes_preserve_errors() {
    let reader = reader_with_data(&[
        0xe1, 0x41, b'n', // map with key "n"
        0x20, 0x05, // pointer to a truncated uint32
        0xc4, 42,
    ]);
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    let plain = lookup.decode_path::<u32>(&path!["n"]).unwrap_err();
    let wrapped = lookup.decode_path::<Wrapped<u32>>(&path!["n"]).unwrap_err();
    assert!(matches!(wrapped, MaxMindDbError::InvalidDatabase { .. }));
    assert_eq!(wrapped.to_string(), plain.to_string());

    let reader = reader_with_data(&[0xe1, 0x41, b'n', 0xc1, 42]);
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    let plain = lookup.decode_path::<String>(&path!["n"]).unwrap_err();
    let wrapped = lookup
        .decode_path::<Wrapped<String>>(&path!["n"])
        .unwrap_err();
    assert!(matches!(&wrapped, MaxMindDbError::Decoding { path: Some(path), .. } if path == "/n"));
    assert_eq!(wrapped.to_string(), plain.to_string());
}

#[test]
fn derived_newtypes_preserve_pointer_depth_limit() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let reader = reader_with_data(&[0x20, 0x00]); // cyclic pointer
            let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
            for error in [
                lookup.decode::<Wrapped<serde_json::Value>>().unwrap_err(),
                lookup
                    .decode_path::<Wrapped<serde_json::Value>>(&[])
                    .unwrap_err(),
            ] {
                assert!(matches!(error, MaxMindDbError::InvalidDatabase { .. }));
                assert!(error
                    .to_string()
                    .contains("exceeded maximum data structure depth"));
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(not(feature = "unsafe-str-decode"))]
#[test]
fn derived_newtypes_validate_pointer_backed_strings() {
    let reader = reader_with_data(&[0x20, 0x02, 0x41, 0xff]);
    let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();
    for error in [
        lookup.decode::<Wrapped<&str>>().unwrap_err(),
        lookup.decode::<Wrapped<String>>().unwrap_err(),
        lookup.decode_path::<Wrapped<&str>>(&[]).unwrap_err(),
        lookup.decode_path::<Wrapped<String>>(&[]).unwrap_err(),
    ] {
        assert!(matches!(error, MaxMindDbError::InvalidDatabase { .. }));
        assert!(error.to_string().contains("invalid UTF-8"));
    }
}
