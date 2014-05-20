#![feature(globs)]
extern crate maxminddb;
extern crate serialize;

use std::io::net::ip::IpAddr;
use std::from_str::FromStr;
use serialize::Decodable;


#[deriving(Decodable, Show)]
struct Continent {
    code: StrBuf,
    geoname_id: u32,
}

#[deriving(Decodable, Show)]
struct GeoIP2City  {
     continent: Continent,
}


fn main() {
    let r = maxminddb::Reader::open("GeoLite2-City.mmdb").unwrap();
    let ip: IpAddr = FromStr::from_str("128.101.101.101").unwrap();
    let dr = r.lookup(ip);
    //print!("{}", dr)

    let mut decoder = maxminddb::Decoder::new(dr.unwrap());
    let decoded_object: GeoIP2City = match Decodable::decode(&mut decoder) {
        Ok(v) => v,
        Err(e) => fail!("Decoding error: {}", e)
    }; // create the final object
    print!("{}\n", decoded_object);

}
