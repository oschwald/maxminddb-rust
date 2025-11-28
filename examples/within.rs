//! Iterate over networks within a CIDR range.
//!
//! Usage: cargo run --example within <database.mmdb> <cidr>
//!
//! Example: cargo run --example within GeoLite2-City.mmdb "89.160.20.0/24"

use ipnetwork::IpNetwork;
use maxminddb::{geoip2, Within};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let mut args = std::env::args().skip(1);
    let db_path = args
        .next()
        .ok_or("First argument must be the path to the IP database")?;

    // Open the database file
    let reader = maxminddb::Reader::open_readfile(db_path)?;

    let cidr_str = args.next().ok_or(
        "Second argument must be the IP address and mask in CIDR notation, e.g. 0.0.0.0/0 or ::/0",
    )?;

    // Parse the CIDR notation
    let ip_net: IpNetwork = cidr_str
        .parse()
        .map_err(|e| format!("Invalid CIDR notation '{}': {}", cidr_str, e))?;

    // Iterate over all networks within the specified range
    let mut n = 0;
    let iter: Within<_> = reader.within(ip_net, Default::default())?;
    for next in iter {
        let lookup = next?;
        let network = lookup.network()?;

        // Skip networks without data
        let Some(info) = lookup.decode::<geoip2::City>()? else {
            continue;
        };

        // Display location hierarchy
        let continent = info.continent.code.unwrap_or("");
        let country = info.country.iso_code.unwrap_or("");
        let city = info.city.names.english.unwrap_or("");
        if !city.is_empty() {
            println!("{} {}-{}-{}", network, continent, country, city);
        } else if !country.is_empty() {
            println!("{} {}-{}", network, continent, country);
        } else if !continent.is_empty() {
            println!("{} {}", network, continent);
        }
        n += 1;
    }
    eprintln!("Processed {} items", n);

    Ok(())
}
