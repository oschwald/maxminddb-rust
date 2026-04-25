//! Basic IP lookup example.
//!
//! Usage: cargo run --example lookup <database.mmdb> <ip_address>

use std::net::IpAddr;

use maxminddb::geoip2;
use maxminddb::path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let mut args = std::env::args().skip(1);
    let db_path = args
        .next()
        .ok_or("First argument must be the path to the IP database")?;

    // Open the database file
    let reader = maxminddb::Reader::open_readfile(db_path)?;

    let ip_str = args
        .next()
        .ok_or("Second argument must be the IP address, like 128.101.101.101")?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|e| format!("Invalid IP address '{}': {}", ip_str, e))?;

    // Look up the IP address. network() returns the matched prefix even
    // when the database has no record for the IP.
    let result = reader.lookup(ip)?;
    println!("Matched network: {}", result.network()?);

    let country_code: Option<&str> = result.decode_path(&path!["country", "iso_code"])?;
    if let Some(country_code) = country_code {
        println!("Country code: {}", country_code);
    }

    // Decode and display city data if present
    if let Some(city) = result.decode::<geoip2::City>()? {
        println!("City data for IP {}: {city:#?}", ip);
    } else {
        println!("No city data found for IP {}", ip);
    }
    Ok(())
}
