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
//! // City lookup - nested structs are always present (default to empty)
//! let result = reader.lookup(ip)?;
//! if let Some(city) = result.decode::<geoip2::City>()? {
//!     // Direct access to nested structs - no Option unwrapping needed
//!     if let Some(name) = city.city.names.english {
//!         println!("City: {}", name);
//!     }
//!     if let Some(code) = city.country.iso_code {
//!         println!("Country: {}", code);
//!     }
//!     // Subdivisions is a Vec, empty if not present
//!     for sub in &city.subdivisions {
//!         if let Some(code) = sub.iso_code {
//!             println!("Subdivision: {}", code);
//!         }
//!     }
//! }
//!
//! // Country-only lookup (smaller/faster)
//! let result = reader.lookup(ip)?;
//! if let Some(country) = result.decode::<geoip2::Country>()? {
//!     if let Some(name) = country.country.names.english {
//!         println!("Country: {}", name);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};

/// Localized names for geographic entities.
///
/// Contains name translations in the languages supported by MaxMind databases.
/// Access names directly via fields like `names.english` or `names.german`.
/// Each field is `Option<&str>` - `None` if not available in that language.
///
/// # Example
///
/// ```
/// use maxminddb::{Reader, geoip2};
/// use std::net::IpAddr;
///
/// let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
/// let ip: IpAddr = "89.160.20.128".parse().unwrap();
/// let result = reader.lookup(ip).unwrap();
///
/// if let Some(city) = result.decode::<geoip2::City>().unwrap() {
///     // Access names directly - Option<&str>
///     if let Some(name) = city.city.names.english {
///         println!("City (en): {}", name);
///     }
///     if let Some(name) = city.city.names.german {
///         println!("City (de): {}", name);
///     }
/// }
/// ```
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Names<'a> {
    /// German name (de)
    #[serde(
        borrow,
        rename = "de",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub german: Option<&'a str>,
    /// English name (en)
    #[serde(rename = "en", default, skip_serializing_if = "Option::is_none")]
    pub english: Option<&'a str>,
    /// Spanish name (es)
    #[serde(rename = "es", default, skip_serializing_if = "Option::is_none")]
    pub spanish: Option<&'a str>,
    /// French name (fr)
    #[serde(rename = "fr", default, skip_serializing_if = "Option::is_none")]
    pub french: Option<&'a str>,
    /// Japanese name (ja)
    #[serde(rename = "ja", default, skip_serializing_if = "Option::is_none")]
    pub japanese: Option<&'a str>,
    /// Brazilian Portuguese name (pt-BR)
    #[serde(rename = "pt-BR", default, skip_serializing_if = "Option::is_none")]
    pub brazilian_portuguese: Option<&'a str>,
    /// Russian name (ru)
    #[serde(rename = "ru", default, skip_serializing_if = "Option::is_none")]
    pub russian: Option<&'a str>,
    /// Simplified Chinese name (zh-CN)
    #[serde(rename = "zh-CN", default, skip_serializing_if = "Option::is_none")]
    pub simplified_chinese: Option<&'a str>,
}

impl Names<'_> {
    /// Returns true if all name fields are `None`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.german.is_none()
            && self.english.is_none()
            && self.spanish.is_none()
            && self.french.is_none()
            && self.japanese.is_none()
            && self.brazilian_portuguese.is_none()
            && self.russian.is_none()
            && self.simplified_chinese.is_none()
    }
}

/// GeoIP2 Country record
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Country<'a> {
    #[serde(borrow, default, skip_serializing_if = "country::Continent::is_empty")]
    pub continent: country::Continent<'a>,
    #[serde(default, skip_serializing_if = "country::Country::is_empty")]
    pub country: country::Country<'a>,
    #[serde(default, skip_serializing_if = "country::Country::is_empty")]
    pub registered_country: country::Country<'a>,
    #[serde(default, skip_serializing_if = "country::RepresentedCountry::is_empty")]
    pub represented_country: country::RepresentedCountry<'a>,
    #[serde(default, skip_serializing_if = "country::Traits::is_empty")]
    pub traits: country::Traits,
}

/// GeoIP2 City record
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct City<'a> {
    #[serde(borrow, default, skip_serializing_if = "city::City::is_empty")]
    pub city: city::City<'a>,
    #[serde(default, skip_serializing_if = "city::Continent::is_empty")]
    pub continent: city::Continent<'a>,
    #[serde(default, skip_serializing_if = "city::Country::is_empty")]
    pub country: city::Country<'a>,
    #[serde(default, skip_serializing_if = "city::Location::is_empty")]
    pub location: city::Location<'a>,
    #[serde(default, skip_serializing_if = "city::Postal::is_empty")]
    pub postal: city::Postal<'a>,
    #[serde(default, skip_serializing_if = "city::Country::is_empty")]
    pub registered_country: city::Country<'a>,
    #[serde(default, skip_serializing_if = "city::RepresentedCountry::is_empty")]
    pub represented_country: city::RepresentedCountry<'a>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subdivisions: Vec<city::Subdivision<'a>>,
    #[serde(default, skip_serializing_if = "city::Traits::is_empty")]
    pub traits: city::Traits,
}

/// GeoIP2 Enterprise record
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Enterprise<'a> {
    #[serde(borrow, default, skip_serializing_if = "enterprise::City::is_empty")]
    pub city: enterprise::City<'a>,
    #[serde(default, skip_serializing_if = "enterprise::Continent::is_empty")]
    pub continent: enterprise::Continent<'a>,
    #[serde(default, skip_serializing_if = "enterprise::Country::is_empty")]
    pub country: enterprise::Country<'a>,
    #[serde(default, skip_serializing_if = "enterprise::Location::is_empty")]
    pub location: enterprise::Location<'a>,
    #[serde(default, skip_serializing_if = "enterprise::Postal::is_empty")]
    pub postal: enterprise::Postal<'a>,
    #[serde(default, skip_serializing_if = "enterprise::Country::is_empty")]
    pub registered_country: enterprise::Country<'a>,
    #[serde(
        default,
        skip_serializing_if = "enterprise::RepresentedCountry::is_empty"
    )]
    pub represented_country: enterprise::RepresentedCountry<'a>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subdivisions: Vec<enterprise::Subdivision<'a>>,
    #[serde(default, skip_serializing_if = "enterprise::Traits::is_empty")]
    pub traits: enterprise::Traits<'a>,
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
    use super::Names;
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Continent<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
    }

    impl Continent<'_> {
        /// Returns true if all fields are empty/None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Country<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
    }

    impl Country<'_> {
        /// Returns true if all fields are empty/None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct RepresentedCountry<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub representation_type: Option<&'a str>,
    }

    impl RepresentedCountry<'_> {
        /// Returns true if all fields are empty/None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Traits {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anonymous_proxy: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anycast: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_satellite_provider: Option<bool>,
    }

    impl Traits {
        /// Returns true if all fields are None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }
}

/// City model structs
pub mod city {
    use super::Names;
    use serde::{Deserialize, Serialize};

    pub use super::country::{Continent, Country, RepresentedCountry, Traits};

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct City<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
    }

    impl City<'_> {
        /// Returns true if all fields are empty/None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Location<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accuracy_radius: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latitude: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub longitude: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub metro_code: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub time_zone: Option<&'a str>,
    }

    impl Location<'_> {
        /// Returns true if all fields are None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Postal<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<&'a str>,
    }

    impl Postal<'_> {
        /// Returns true if all fields are None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Subdivision<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
    }

    impl Subdivision<'_> {
        /// Returns true if all fields are empty/None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }
}

/// Enterprise model structs
pub mod enterprise {
    use super::Names;
    use serde::{Deserialize, Serialize};

    pub use super::country::{Continent, RepresentedCountry};

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct City<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
    }

    impl City<'_> {
        /// Returns true if all fields are empty/None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Country<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
    }

    impl Country<'_> {
        /// Returns true if all fields are empty/None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Location<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accuracy_radius: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latitude: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub longitude: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub metro_code: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub time_zone: Option<&'a str>,
    }

    impl Location<'_> {
        /// Returns true if all fields are None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Postal<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
    }

    impl Postal<'_> {
        /// Returns true if all fields are None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Subdivision<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
    }

    impl Subdivision<'_> {
        /// Returns true if all fields are empty/None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Traits<'a> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autonomous_system_number: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autonomous_system_organization: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connection_type: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub domain: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anonymous: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anonymous_proxy: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anonymous_vpn: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anycast: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_hosting_provider: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub isp: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_public_proxy: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_residential_proxy: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_satellite_provider: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_tor_exit_node: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mobile_country_code: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mobile_network_code: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub organization: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user_type: Option<&'a str>,
    }

    impl Traits<'_> {
        /// Returns true if all fields are None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }
}
