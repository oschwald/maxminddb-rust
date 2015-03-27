#![feature(collections)]
#![feature(old_io)]

extern crate collections;
extern crate maxminddb;
extern crate rustc_serialize;

use std::old_io::net::ip::IpAddr;
use std::str::FromStr;

use rustc_serialize::Decodable;

#[derive(RustcDecodable, Debug)]
pub struct Names {
    en: Option<String>,
}

#[derive(RustcDecodable, Debug)]
pub struct Continent {
    code: Option<String>,
    geoname_id: Option<u32>,
    names: Option<Names>,
}

#[derive(RustcDecodable, Debug)]
pub struct Place {
    geoname_id: Option<u32>,
    iso_code: Option<String>,
    names: Option<Names>,
}

#[derive(Copy, RustcDecodable, Debug)]
pub struct Traits {
    is_anonymous_proxy: Option<bool>,
    is_satellite_provider: Option<bool>,
}

#[derive(RustcDecodable, Debug)]
pub struct Country {
    city: Option<Place>,
    continent: Option<Continent>,
    country: Option<Place>,
    registered_country: Option<Place>,
    represented_country: Option<Place>,
    traits: Option<Traits>,
}

fn main() {
    let r = maxminddb::Reader::open("/usr/local/share/GeoIP/GeoIP2-City.mmdb").ok().unwrap();
    let ip: IpAddr = FromStr::from_str("128.101.101.101").unwrap();
    let dr = r.lookup(ip);

    let mut decoder = maxminddb::Decoder::new(dr.ok().unwrap());
    let decoded_object: Country = match Decodable::decode(&mut decoder) {
        Ok(v) => v,
        Err(e) => panic!("Decoding error: {:?}", e)
    }; // create the final object
    print!("{:?}\n", decoded_object);

}
