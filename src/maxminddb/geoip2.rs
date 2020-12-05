use serde::{Deserialize, Serialize};

/// GeoIP2 Country record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Country<'a> {
    #[serde(borrow)]
    pub continent: Option<model::Continent<'a>>,
    pub country: Option<model::Country<'a>>,
    pub registered_country: Option<model::Country<'a>>,
    pub represented_country: Option<model::RepresentedCountry<'a>>,
    pub traits: Option<model::Traits>,
}

/// GeoIP2 City record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct City<'a> {
    pub city: Option<model::City<'a>>,
    #[serde(borrow)]
    pub continent: Option<model::Continent<'a>>,
    pub country: Option<model::Country<'a>>,
    pub location: Option<model::Location<'a>>,
    pub postal: Option<model::Postal<'a>>,
    pub registered_country: Option<model::Country<'a>>,
    pub represented_country: Option<model::RepresentedCountry<'a>>,
    pub subdivisions: Option<Vec<model::Subdivision<'a>>>,
    pub traits: Option<model::Traits>,
}

/// GeoIP2 ISP record
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Isp<'a> {
    pub autonomous_system_number: Option<u32>,
    pub autonomous_system_organization: Option<&'a str>,
    pub isp: Option<&'a str>,
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

pub mod model {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct City<'a> {
        pub geoname_id: Option<u32>,
        #[serde(borrow)]
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

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
    pub struct Location<'a> {
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
    pub struct RepresentedCountry<'a> {
        pub geoname_id: Option<u32>,
        pub iso_code: Option<&'a str>,
        pub names: Option<BTreeMap<&'a str, &'a str>>, // pub type: Option<&'a str>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Subdivision<'a> {
        pub geoname_id: Option<u32>,
        pub iso_code: Option<&'a str>,
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Traits {
        pub is_anonymous_proxy: Option<bool>,
        pub is_satellite_provider: Option<bool>,
    }
}
