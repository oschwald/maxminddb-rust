extern crate maxminddb;
extern crate rustc_serialize;

use std::net::SocketAddr;
use std::str::FromStr;

use maxminddb::geoip2;

fn main() {
    let reader = maxminddb::Reader::open("/usr/local/share/GeoIP/GeoIP2-City.mmdb").unwrap();
    let ip: SocketAddr = FromStr::from_str("128.101.101.101:0").unwrap();
    let city: geoip2::City = reader.lookup(ip).unwrap();
    print!("{:?}\n", city);
}
