#![crate_name = "geoip2"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

extern crate collections;
extern crate maxminddb;
extern crate "rustc-serialize" as rustc_serialize;

#[deriving(RustcDecodable, Show)]
pub struct Names {
    en: Option<String>,
}

#[deriving(RustcDecodable, Show)]
pub struct Continent {
    code: Option<String>,
    geoname_id: Option<uint>,
    names: Option<Names>,
}

#[deriving(RustcDecodable, Show)]
pub struct Place {
    geoname_id: Option<uint>,
    iso_code: Option<String>,
    names: Option<Names>,
}

#[deriving(Copy, RustcDecodable, Show)]
pub struct Traits {
    is_anonymous_proxy: Option<bool>,
    is_satellite_provider: Option<bool>,
}

#[deriving(RustcDecodable, Show)]
pub struct Country {
    continent: Option<Continent>,
    country: Option<Place>,
    registered_country: Option<Place>,
    represented_country: Option<Place>,
    traits: Option<Traits>,
}
