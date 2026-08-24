#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

fuzz_target!(|data: &[u8]| {
    let _ = maxminddb::fuzzing::decode::<common::FuzzValue>(data);
    let _ = maxminddb::fuzzing::verify(data);
});
