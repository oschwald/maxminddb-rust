use serde::{Deserialize, Serialize};

/// GeoIP2 Country record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Country<'a> {
    #[serde(borrow)]
    pub continent: Option<country::Continent<'a>>,
    pub country: Option<country::Country<'a>>,
    pub registered_country: Option<country::Country<'a>>,
    pub represented_country: Option<country::RepresentedCountry<'a>>,
    pub traits: Option<country::Traits>,
}

/// GeoIP2 City record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct City<'a> {
    #[serde(borrow)]
    pub city: Option<city::City<'a>>,
    pub continent: Option<city::Continent<'a>>,
    pub country: Option<city::Country<'a>>,
    pub location: Option<city::Location<'a>>,
    pub postal: Option<city::Postal<'a>>,
    pub registered_country: Option<city::Country<'a>>,
    pub represented_country: Option<city::RepresentedCountry<'a>>,
    pub subdivisions: Option<Vec<city::Subdivision<'a>>>,
    pub traits: Option<city::Traits>,
}

/// GeoIP2 Enterprise record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Enterprise<'a> {
    #[serde(borrow)]
    pub city: Option<enterprise::City<'a>>,
    pub continent: Option<enterprise::Continent<'a>>,
    pub country: Option<enterprise::Country<'a>>,
    pub location: Option<enterprise::Location<'a>>,
    pub postal: Option<enterprise::Postal<'a>>,
    pub registered_country: Option<enterprise::Country<'a>>,
    pub represented_country: Option<enterprise::RepresentedCountry<'a>>,
    pub subdivisions: Option<Vec<enterprise::Subdivision<'a>>>,
    pub traits: Option<enterprise::Traits<'a>>,
}

/// GeoIP2 ISP record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Isp<'a> {
    pub autonomous_system_number: Option<u32>,
    pub autonomous_system_organization: Option<&'a str>,
    pub isp: Option<&'a str>,
    pub mobile_country_code: Option<&'a str>,
    pub mobile_network_code: Option<&'a str>,
    pub organization: Option<&'a str>,
}

/// GeoIP2 Connection-Type record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ConnectionType<'a> {
    pub connection_type: Option<&'a str>,
}

/// GeoIP2 Anonymous Ip record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AnonymousIp {
    pub is_anonymous: Option<bool>,
    pub is_anonymous_vpn: Option<bool>,
    pub is_hosting_provider: Option<bool>,
    pub is_public_proxy: Option<bool>,
    pub is_residential_proxy: Option<bool>,
    pub is_tor_exit_node: Option<bool>,
}

/// GeoIP2 DensityIncome record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DensityIncome {
    pub average_income: Option<u32>,
    pub population_density: Option<u32>,
}

/// GeoIP2 Domain record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Domain<'a> {
    pub domain: Option<&'a str>,
}

/// GeoIP2 Asn record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Asn<'a> {
    pub autonomous_system_number: Option<u32>,
    pub autonomous_system_organization: Option<&'a str>,
}

/// Country model structs
pub mod country {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Continent<'a> {
        pub code: Option<&'a str>,
        pub geoname_id: Option<u32>,
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Country<'a> {
        pub geoname_id: Option<u32>,
        pub is_in_european_union: Option<bool>,
        pub iso_code: Option<&'a str>,
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct RepresentedCountry<'a> {
        pub geoname_id: Option<u32>,
        pub is_in_european_union: Option<bool>,
        pub iso_code: Option<&'a str>,
        pub names: Option<BTreeMap<&'a str, &'a str>>,
        #[serde(rename = "type")]
        pub representation_type: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Traits {
        pub is_anonymous_proxy: Option<bool>,
        pub is_satellite_provider: Option<bool>,
    }
}

/// Country model structs
pub mod city {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    pub use super::country::{Continent, Country, RepresentedCountry, Traits};

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct City<'a> {
        pub geoname_id: Option<u32>,
        #[serde(borrow)]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Location<'a> {
        pub accuracy_radius: Option<u16>,
        pub latitude: Option<f64>,
        pub longitude: Option<f64>,
        pub metro_code: Option<u16>,
        pub time_zone: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Postal<'a> {
        pub code: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Subdivision<'a> {
        pub geoname_id: Option<u32>,
        pub iso_code: Option<&'a str>,
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
        pub confidence: Option<u8>,
        pub geoname_id: Option<u32>,
        #[serde(borrow)]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Country<'a> {
        pub confidence: Option<u8>,
        pub geoname_id: Option<u32>,
        pub is_in_european_union: Option<bool>,
        pub iso_code: Option<&'a str>,
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Location<'a> {
        pub accuracy_radius: Option<u16>,
        pub latitude: Option<f64>,
        pub longitude: Option<f64>,
        pub metro_code: Option<u16>,
        pub time_zone: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Postal<'a> {
        pub code: Option<&'a str>,
        pub confidence: Option<u8>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Subdivision<'a> {
        pub confidence: Option<u8>,
        pub geoname_id: Option<u32>,
        pub iso_code: Option<&'a str>,
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Traits<'a> {
        pub autonomous_system_number: Option<u32>,
        pub autonomous_system_organization: Option<&'a str>,
        pub connection_type: Option<&'a str>,
        pub domain: Option<&'a str>,
        pub is_anonymous: Option<bool>,
        pub is_anonymous_proxy: Option<bool>,
        pub is_anonymous_vpn: Option<bool>,
        pub is_hosting_provider: Option<bool>,
        pub isp: Option<&'a str>,
        pub is_public_proxy: Option<bool>,
        pub is_residential_proxy: Option<bool>,
        pub is_satellite_provider: Option<bool>,
        pub is_tor_exit_node: Option<bool>,
        pub mobile_country_code: Option<&'a str>,
        pub mobile_network_code: Option<&'a str>,
        pub organization: Option<&'a str>,
        pub user_type: Option<&'a str>,
    }
}
