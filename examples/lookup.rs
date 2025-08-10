use std::net::IpAddr;

use maxminddb::geoip2;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let db_path = args
        .next()
        .ok_or("First argument must be the path to the IP database")?;
    let reader = maxminddb::Reader::open_readfile(db_path)?;

    let ip_str = args
        .next()
        .ok_or("Second argument must be the IP address, like 128.101.101.101")?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|e| format!("Invalid IP address '{}': {}", ip_str, e))?;

    match reader.lookup::<geoip2::City>(ip)? {
        Some(city) => {
            println!("City data for IP {}: {city:#?}", ip);
        }
        None => {
            println!("No city data found for IP {}", ip);
        }
    }
    Ok(())
}
