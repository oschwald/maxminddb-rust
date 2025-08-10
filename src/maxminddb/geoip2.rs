//! GeoIP2 and GeoLite2 database record structures
//!
//! This module provides strongly-typed Rust structures that correspond to the
//! various GeoIP2 and GeoLite2 database record formats.
//!
//! # Record Types
//!
//! - [`City`] - Complete city-level geolocation data (most comprehensive)
//! - [`Country`] - Country-level geolocation data
//! - [`Enterprise`] - Enterprise database with additional confidence scores
//! - [`Isp`] - Internet Service Provider information
//! - [`AnonymousIp`] - Anonymous proxy and VPN detection
//! - [`ConnectionType`] - Connection type classification
//! - [`Domain`] - Domain information
//! - [`Asn`] - Autonomous System Number data
//! - [`DensityIncome`] - Population density and income data
//!
//! # Usage Examples
//!
//! ```rust
//! use maxminddb::{Reader, geoip2};
//! use std::net::IpAddr;
//!
//! # fn main() -> Result<(), maxminddb::MaxMindDbError> {
//! let reader = Reader::open_readfile(
//!     "test-data/test-data/GeoIP2-City-Test.mmdb")?;
//! let ip: IpAddr = "89.160.20.128".parse().unwrap();
//!
//! // City lookup (most common)
//! if let Some(city) = reader.lookup::<geoip2::City>(ip)? {
//!     if let Some(city_names) = city.city.and_then(|c| c.names) {
//!         if let Some(city_name) = city_names.get("en") {
//!             println!("City: {}", city_name);
//!         }
//!     }
//!     if let Some(country_code) = city.country.and_then(|c| c.iso_code) {
//!         println!("Country: {}", country_code);
//!     }
//! }
//!
//! // Country-only lookup (smaller/faster)
//! if let Some(country) = reader.lookup::<geoip2::Country>(ip)? {
//!     if let Some(country_names) = country.country.and_then(|c| c.names) {
//!         if let Some(country_name) = country_names.get("en") {
//!             println!("Country: {}", country_name);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};

/// GeoIP2 Country record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Country<'a> {
    #[serde(borrow)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continent: Option<country::Continent<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<country::Country<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_country: Option<country::Country<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub represented_country: Option<country::RepresentedCountry<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traits: Option<country::Traits>,
}

/// GeoIP2 City record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct City<'a> {
    #[serde(borrow)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<city::City<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continent: Option<city::Continent<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<city::Country<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<city::Location<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal: Option<city::Postal<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_country: Option<city::Country<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub represented_country: Option<city::RepresentedCountry<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdivisions: Option<Vec<city::Subdivision<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traits: Option<city::Traits>,
}

/// GeoIP2 Enterprise record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Enterprise<'a> {
    #[serde(borrow)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<enterprise::City<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continent: Option<enterprise::Continent<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<enterprise::Country<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<enterprise::Location<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal: Option<enterprise::Postal<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_country: Option<enterprise::Country<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub represented_country: Option<enterprise::RepresentedCountry<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdivisions: Option<Vec<enterprise::Subdivision<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traits: Option<enterprise::Traits<'a>>,
}

/// GeoIP2 ISP record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Isp<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_organization: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_country_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_network_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<&'a str>,
}

/// GeoIP2 Connection-Type record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ConnectionType<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<&'a str>,
}

/// GeoIP2 Anonymous Ip record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AnonymousIp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_anonymous: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_anonymous_vpn: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_hosting_provider: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public_proxy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_residential_proxy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_tor_exit_node: Option<bool>,
}

/// GeoIP2 DensityIncome record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DensityIncome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_income: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub population_density: Option<u32>,
}

/// GeoIP2 Domain record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Domain<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<&'a str>,
}

/// GeoIP2 Asn record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Asn<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_organization: Option<&'a str>,
}

/// Country model structs
pub mod country {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Continent<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Country<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct RepresentedCountry<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
        #[serde(rename = "type")]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub representation_type: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Traits {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_anonymous_proxy: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_anycast: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_satellite_provider: Option<bool>,
    }
}

/// City model structs
pub mod city {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    pub use super::country::{Continent, Country, RepresentedCountry, Traits};

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct City<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(borrow)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Location<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub accuracy_radius: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub latitude: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub longitude: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub metro_code: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub time_zone: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Postal<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub code: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Subdivision<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }
}

/// Enterprise model structs
pub mod enterprise {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    pub use super::country::{Continent, RepresentedCountry};

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct City<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(borrow)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Country<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Location<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub accuracy_radius: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub latitude: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub longitude: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub metro_code: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub time_zone: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Postal<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Subdivision<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Traits<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub autonomous_system_number: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub autonomous_system_organization: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub connection_type: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub domain: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_anonymous: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_anonymous_proxy: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_anonymous_vpn: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_anycast: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_hosting_provider: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub isp: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_public_proxy: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_residential_proxy: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_satellite_provider: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_tor_exit_node: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mobile_country_code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mobile_network_code: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub organization: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_type: Option<&'a str>,
    }
}
