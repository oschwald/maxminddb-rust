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

/// GeoIP2/GeoLite2 Country database record.
///
/// Contains country-level geolocation data for an IP address. This is the
/// simplest geolocation record type, suitable when you only need country
/// information.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Country<'a> {
    /// Continent data for the IP address.
    #[serde(borrow, default, skip_serializing_if = "country::Continent::is_empty")]
    pub continent: country::Continent<'a>,
    /// Country where MaxMind believes the IP is located.
    #[serde(default, skip_serializing_if = "country::Country::is_empty")]
    pub country: country::Country<'a>,
    /// Country where the ISP has registered the IP block.
    /// May differ from `country` (e.g., for mobile networks or VPNs).
    #[serde(default, skip_serializing_if = "country::Country::is_empty")]
    pub registered_country: country::Country<'a>,
    /// Country represented by users of this IP (e.g., military base or embassy).
    #[serde(default, skip_serializing_if = "country::RepresentedCountry::is_empty")]
    pub represented_country: country::RepresentedCountry<'a>,
    /// Various traits associated with the IP address.
    #[serde(default, skip_serializing_if = "country::Traits::is_empty")]
    pub traits: country::Traits,
}

/// GeoIP2/GeoLite2 City database record.
///
/// Contains city-level geolocation data including location coordinates,
/// postal code, subdivisions (states/provinces), and country information.
/// This is the most comprehensive free geolocation record type.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct City<'a> {
    /// City data for the IP address.
    #[serde(borrow, default, skip_serializing_if = "city::City::is_empty")]
    pub city: city::City<'a>,
    /// Continent data for the IP address.
    #[serde(default, skip_serializing_if = "city::Continent::is_empty")]
    pub continent: city::Continent<'a>,
    /// Country where MaxMind believes the IP is located.
    #[serde(default, skip_serializing_if = "city::Country::is_empty")]
    pub country: city::Country<'a>,
    /// Location data including coordinates and time zone.
    #[serde(default, skip_serializing_if = "city::Location::is_empty")]
    pub location: city::Location<'a>,
    /// Postal code data for the IP address.
    #[serde(default, skip_serializing_if = "city::Postal::is_empty")]
    pub postal: city::Postal<'a>,
    /// Country where the ISP has registered the IP block.
    #[serde(default, skip_serializing_if = "city::Country::is_empty")]
    pub registered_country: city::Country<'a>,
    /// Country represented by users of this IP (e.g., military base or embassy).
    #[serde(default, skip_serializing_if = "city::RepresentedCountry::is_empty")]
    pub represented_country: city::RepresentedCountry<'a>,
    /// Subdivisions (states, provinces, etc.) ordered from largest to smallest.
    /// For example, Oxford, UK would have England first, then Oxfordshire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subdivisions: Vec<city::Subdivision<'a>>,
    /// Various traits associated with the IP address.
    #[serde(default, skip_serializing_if = "city::Traits::is_empty")]
    pub traits: city::Traits,
}

/// GeoIP2 Enterprise database record.
///
/// Contains all City data plus additional confidence scores and traits.
/// Enterprise records include confidence values (0-100) indicating MaxMind's
/// certainty about the accuracy of each field.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Enterprise<'a> {
    /// City data with confidence score.
    #[serde(borrow, default, skip_serializing_if = "enterprise::City::is_empty")]
    pub city: enterprise::City<'a>,
    /// Continent data for the IP address.
    #[serde(default, skip_serializing_if = "enterprise::Continent::is_empty")]
    pub continent: enterprise::Continent<'a>,
    /// Country data with confidence score.
    #[serde(default, skip_serializing_if = "enterprise::Country::is_empty")]
    pub country: enterprise::Country<'a>,
    /// Location data including coordinates and time zone.
    #[serde(default, skip_serializing_if = "enterprise::Location::is_empty")]
    pub location: enterprise::Location<'a>,
    /// Postal code data with confidence score.
    #[serde(default, skip_serializing_if = "enterprise::Postal::is_empty")]
    pub postal: enterprise::Postal<'a>,
    /// Country where the ISP has registered the IP block.
    #[serde(default, skip_serializing_if = "enterprise::Country::is_empty")]
    pub registered_country: enterprise::Country<'a>,
    /// Country represented by users of this IP (e.g., military base or embassy).
    #[serde(
        default,
        skip_serializing_if = "enterprise::RepresentedCountry::is_empty"
    )]
    pub represented_country: enterprise::RepresentedCountry<'a>,
    /// Subdivisions with confidence scores, ordered from largest to smallest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subdivisions: Vec<enterprise::Subdivision<'a>>,
    /// Extended traits including ISP, organization, and connection information.
    #[serde(default, skip_serializing_if = "enterprise::Traits::is_empty")]
    pub traits: enterprise::Traits<'a>,
}

/// GeoIP2 ISP database record.
///
/// Contains Internet Service Provider and organization information for an IP.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Isp<'a> {
    /// The autonomous system number (ASN) for the IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_number: Option<u32>,
    /// The organization associated with the registered ASN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_organization: Option<&'a str>,
    /// The name of the ISP associated with the IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<&'a str>,
    /// The mobile country code (MCC) associated with the IP.
    /// See <https://en.wikipedia.org/wiki/Mobile_country_code>.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_country_code: Option<&'a str>,
    /// The mobile network code (MNC) associated with the IP.
    /// See <https://en.wikipedia.org/wiki/Mobile_network_code>.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_network_code: Option<&'a str>,
    /// The name of the organization associated with the IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<&'a str>,
}

/// GeoIP2 Connection-Type database record.
///
/// Contains the connection type for an IP address.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ConnectionType<'a> {
    /// The connection type. Possible values include "Dialup", "Cable/DSL",
    /// "Corporate", "Cellular", and "Satellite". Additional values may be
    /// added in the future.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<&'a str>,
}

/// GeoIP2 Anonymous IP database record.
///
/// Contains information about whether an IP address is associated with
/// anonymous or proxy services.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AnonymousIp {
    /// True if the IP belongs to any sort of anonymous network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_anonymous: Option<bool>,
    /// True if the IP is registered to an anonymous VPN provider.
    /// Note: If a VPN provider does not register subnets under names associated
    /// with them, we will likely only flag their IP ranges using `is_hosting_provider`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_anonymous_vpn: Option<bool>,
    /// True if the IP belongs to a hosting or VPN provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_hosting_provider: Option<bool>,
    /// True if the IP belongs to a public proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public_proxy: Option<bool>,
    /// True if the IP is on a suspected anonymizing network and belongs to
    /// a residential ISP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_residential_proxy: Option<bool>,
    /// True if the IP is a Tor exit node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_tor_exit_node: Option<bool>,
}

/// GeoIP2 DensityIncome database record.
///
/// Contains population density and income data for an IP address location.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DensityIncome {
    /// The average income in US dollars associated with the IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_income: Option<u32>,
    /// The estimated number of people per square kilometer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub population_density: Option<u32>,
}

/// GeoIP2 Domain database record.
///
/// Contains the second-level domain associated with an IP address.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Domain<'a> {
    /// The second-level domain associated with the IP address
    /// (e.g., "example.com").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<&'a str>,
}

/// GeoLite2 ASN database record.
///
/// Contains Autonomous System Number (ASN) data for an IP address.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Asn<'a> {
    /// The autonomous system number for the IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_number: Option<u32>,
    /// The organization associated with the registered ASN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_organization: Option<&'a str>,
}

/// Country/City database model structs.
///
/// These structs are used by both [`super::Country`] and [`super::City`] records.
pub mod country {
    use super::Names;
    use serde::{Deserialize, Serialize};

    /// Continent data for an IP address.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Continent<'a> {
        /// Two-character continent code (e.g., "NA" for North America, "EU" for Europe).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<&'a str>,
        /// GeoNames ID for the continent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        /// Localized continent names.
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

    /// Country data for an IP address.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Country<'a> {
        /// GeoNames ID for the country.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        /// True if the country is a member state of the European Union.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        /// Two-character ISO 3166-1 alpha-2 country code.
        /// See <https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        /// Localized country names.
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

    /// Represented country data.
    ///
    /// The represented country is the country represented by something like a
    /// military base or embassy.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct RepresentedCountry<'a> {
        /// GeoNames ID for the represented country.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        /// True if the represented country is a member state of the European Union.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        /// Two-character ISO 3166-1 alpha-2 country code.
        /// See <https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        /// Localized country names.
        #[serde(borrow, default, skip_serializing_if = "Names::is_empty")]
        pub names: Names<'a>,
        /// Type of entity representing the country (e.g., "military").
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

    /// Traits data for Country/City records.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Traits {
        /// True if the IP belongs to an anycast network.
        /// See <https://en.wikipedia.org/wiki/Anycast>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anycast: Option<bool>,
    }

    impl Traits {
        /// Returns true if all fields are None.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            *self == Self::default()
        }
    }
}

/// City database model structs.
///
/// City-specific structs. Country-level structs are re-exported from [`super::country`].
pub mod city {
    use super::Names;
    use serde::{Deserialize, Serialize};

    pub use super::country::{Continent, Country, RepresentedCountry, Traits};

    /// City data for an IP address.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct City<'a> {
        /// GeoNames ID for the city.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        /// Localized city names.
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

    /// Location data for an IP address.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Location<'a> {
        /// Approximate accuracy radius in kilometers around the coordinates.
        /// This is the radius where we have a 67% confidence that the device
        /// using the IP address resides within.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accuracy_radius: Option<u16>,
        /// Approximate latitude of the location. This value is not precise and
        /// should not be used to identify a particular address or household.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latitude: Option<f64>,
        /// Approximate longitude of the location. This value is not precise and
        /// should not be used to identify a particular address or household.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub longitude: Option<f64>,
        /// Metro code for the location, used for targeting advertisements.
        ///
        /// **Deprecated:** Metro codes are no longer maintained and should not be used.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub metro_code: Option<u16>,
        /// Time zone associated with the location, as specified by the
        /// IANA Time Zone Database (e.g., "America/New_York").
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

    /// Postal data for an IP address.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Postal<'a> {
        /// Postal code for the location. Not available for all countries.
        /// In some countries, this will only contain part of the postal code.
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

    /// Subdivision (state, province, etc.) data for an IP address.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Subdivision<'a> {
        /// GeoNames ID for the subdivision.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        /// ISO 3166-2 subdivision code (up to 3 characters).
        /// See <https://en.wikipedia.org/wiki/ISO_3166-2>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        /// Localized subdivision names.
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

/// Enterprise database model structs.
///
/// Enterprise-specific structs with confidence scores. Some structs are
/// re-exported from [`super::country`].
pub mod enterprise {
    use super::Names;
    use serde::{Deserialize, Serialize};

    pub use super::country::{Continent, RepresentedCountry};

    /// City data with confidence score.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct City<'a> {
        /// Confidence score (0-100) indicating MaxMind's certainty that the
        /// city is correct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        /// GeoNames ID for the city.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        /// Localized city names.
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

    /// Country data with confidence score.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Country<'a> {
        /// Confidence score (0-100) indicating MaxMind's certainty that the
        /// country is correct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        /// GeoNames ID for the country.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        /// True if the country is a member state of the European Union.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_in_european_union: Option<bool>,
        /// Two-character ISO 3166-1 alpha-2 country code.
        /// See <https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        /// Localized country names.
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

    /// Location data for an IP address.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Location<'a> {
        /// Approximate accuracy radius in kilometers around the coordinates.
        /// This is the radius where we have a 67% confidence that the device
        /// using the IP address resides within.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accuracy_radius: Option<u16>,
        /// Approximate latitude of the location. This value is not precise and
        /// should not be used to identify a particular address or household.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latitude: Option<f64>,
        /// Approximate longitude of the location. This value is not precise and
        /// should not be used to identify a particular address or household.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub longitude: Option<f64>,
        /// Metro code for the location, used for targeting advertisements.
        ///
        /// **Deprecated:** Metro codes are no longer maintained and should not be used.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub metro_code: Option<u16>,
        /// Time zone associated with the location, as specified by the
        /// IANA Time Zone Database (e.g., "America/New_York").
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

    /// Postal data with confidence score.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Postal<'a> {
        /// Postal code for the location. Not available for all countries.
        /// In some countries, this will only contain part of the postal code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<&'a str>,
        /// Confidence score (0-100) indicating MaxMind's certainty that the
        /// postal code is correct.
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

    /// Subdivision data with confidence score.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Subdivision<'a> {
        /// Confidence score (0-100) indicating MaxMind's certainty that the
        /// subdivision is correct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        /// GeoNames ID for the subdivision.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geoname_id: Option<u32>,
        /// ISO 3166-2 subdivision code (up to 3 characters).
        /// See <https://en.wikipedia.org/wiki/ISO_3166-2>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso_code: Option<&'a str>,
        /// Localized subdivision names.
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

    /// Extended traits data for Enterprise records.
    ///
    /// Contains ISP, organization, connection type, and anonymity information.
    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    pub struct Traits<'a> {
        /// The autonomous system number (ASN) for the IP address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autonomous_system_number: Option<u32>,
        /// The organization associated with the registered ASN.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autonomous_system_organization: Option<&'a str>,
        /// The connection type. Possible values include "Dialup", "Cable/DSL",
        /// "Corporate", "Cellular", and "Satellite".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connection_type: Option<&'a str>,
        /// The second-level domain associated with the IP address
        /// (e.g., "example.com").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub domain: Option<&'a str>,
        /// True if the IP belongs to any sort of anonymous network.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anonymous: Option<bool>,
        /// True if the IP is registered to an anonymous VPN provider.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anonymous_vpn: Option<bool>,
        /// True if the IP belongs to an anycast network.
        /// See <https://en.wikipedia.org/wiki/Anycast>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_anycast: Option<bool>,
        /// True if the IP belongs to a hosting or VPN provider.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_hosting_provider: Option<bool>,
        /// The name of the ISP associated with the IP address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub isp: Option<&'a str>,
        /// True if the IP belongs to a public proxy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_public_proxy: Option<bool>,
        /// True if the IP is on a suspected anonymizing network and belongs to
        /// a residential ISP.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_residential_proxy: Option<bool>,
        /// True if the IP is a Tor exit node.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_tor_exit_node: Option<bool>,
        /// The mobile country code (MCC) associated with the IP.
        /// See <https://en.wikipedia.org/wiki/Mobile_country_code>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mobile_country_code: Option<&'a str>,
        /// The mobile network code (MNC) associated with the IP.
        /// See <https://en.wikipedia.org/wiki/Mobile_network_code>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mobile_network_code: Option<&'a str>,
        /// The name of the organization associated with the IP address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub organization: Option<&'a str>,
        /// The user type associated with the IP address. Possible values include
        /// "business", "cafe", "cellular", "college", "government", "hosting",
        /// "library", "military", "residential", "router", "school",
        /// "search_engine_spider", and "traveler".
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
