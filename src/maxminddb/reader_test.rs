use super::{InvalidDatabaseError, Reader, Decoder, IoError};
use std::io::net::ip::IpAddr;
use std::from_str::FromStr;
use serialize::Decodable;

#[test]
fn test_decoder() {

    #[deriving(Decodable, Show, Eq)]
    struct MapXType {
        arrayX: ~[uint],
        utf8_stringX: ~str
    };

    #[deriving(Decodable, Show, Eq)]
    struct MapType {
        mapX: MapXType
    };

    #[deriving(Decodable, Show)]
    struct TestType {
        array:       ~[uint],
        boolean:     bool,
        bytes:       ~[u8],
        double:      f64,
        float:       f32,
        int32:       i32,
        map:         MapType,
        uint16:      u16,
        uint32:      u32,
        uint64:      u64,
        uint128:     ~[u8],
        utf8_string: ~str
    }

    let r = Reader::open("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
    let ip: IpAddr = FromStr::from_str("::1.1.1.0").unwrap();
    let raw_data = r.lookup(ip);

    let mut decoder = Decoder::new(raw_data.unwrap());
    let result: TestType = match Decodable::decode(&mut decoder) {
        Ok(v) => v,
        Err(e) => fail!("Decoding error: {}", e)
    };

    assert_eq!(result.array, ~[ 1u, 2u, 3u ]);
    assert_eq!(result.boolean, true);
    assert_eq!(result.bytes, ~[0u8, 0u8, 0u8, 42u8])
    assert_eq!(result.double, 42.123456);
    assert_eq!(result.float, 1.1);
    assert_eq!(result.int32, -268435456);

    assert_eq!(result.map, MapType{ mapX: MapXType{ arrayX: ~[7,8,9], utf8_stringX: "hello".to_owned()}});

    assert_eq!(result.uint16, 100);
    assert_eq!(result.uint32, 268435456);
    assert_eq!(result.uint64, 1152921504606846976);
    assert_eq!(result.uint128, ~[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    assert_eq!(result.utf8_string,  "unicode! ☯ - ♫".to_owned());
}

#[test]
fn test_broken_database() {
    let r = Reader::open("test-data/test-data/GeoIP2-City-Test-Broken-Double-Format.mmdb").unwrap();
    let ip: IpAddr = FromStr::from_str("2001:220::").unwrap();
    let result = r.lookup(ip);
    assert_eq!(result, Err(InvalidDatabaseError("double of size 2".to_owned())));
}

#[test]
fn test_missing_database() {
    let r = Reader::open("file-does-not-exist.mmdb");
    match r {
        Ok(_) => fail!("Received Reader when opening non-existent file"),
        Err(IoError(_)) => assert!(true),
        Err(_) => assert!(false)
    }
}


#[test]
fn test_non_database() {
    let r = Reader::open("README.md");
    match r {
        Ok(_) => fail!("Received Reader when opening a non-MMDB file"),
        Err(e) => assert_eq!(e, InvalidDatabaseError("Could not find MaxMind DB metadata in file.".to_owned()))

    }
}

