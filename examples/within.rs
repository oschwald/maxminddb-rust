use ipnetwork::IpNetwork;
use maxminddb::{geoip2, Within};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let db_path = args
        .next()
        .ok_or("First argument must be the path to the IP database")?;
    let reader = maxminddb::Reader::open_readfile(db_path)?;

    let cidr_str = args.next().ok_or(
        "Second argument must be the IP address and mask in CIDR notation, e.g. 0.0.0.0/0 or ::/0",
    )?;

    let ip_net: IpNetwork = cidr_str
        .parse()
        .map_err(|e| format!("Invalid CIDR notation '{}': {}", cidr_str, e))?;

    let mut n = 0;
    let iter: Within<_> = reader.within(ip_net, Default::default())?;
    for next in iter {
        let lookup = next?;
        let network = lookup.network()?;
        let info: geoip2::City = lookup.decode()?;

        let continent = info.continent.and_then(|c| c.code).unwrap_or("");
        let country = info.country.and_then(|c| c.iso_code).unwrap_or("");
        let city = match info.city.and_then(|c| c.names) {
            Some(names) => names.get("en").unwrap_or(&""),
            None => "",
        };
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
