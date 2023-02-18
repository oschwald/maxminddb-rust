use ipnetwork::IpNetwork;
use maxminddb::{geoip2, Within};

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let reader = maxminddb::Reader::open_readfile(
        args.next()
            .ok_or("First argument must be the path to the IP database")?,
    )
    .unwrap();
    let cidr: String = args
        .next()
        .ok_or("Second argument must be the IP address and mask in CIDR notation, e.g. 0.0.0.0/0 or ::/0")?
        .parse()
        .unwrap();
    let ip_net = if cidr.contains(':') {
        IpNetwork::V6(cidr.parse().unwrap())
    } else {
        IpNetwork::V4(cidr.parse().unwrap())
    };

    let mut n = 0;
    let iter: Within<geoip2::City, _> = reader.within(ip_net).map_err(|e| e.to_string())?;
    for next in iter {
        let item = next.map_err(|e| e.to_string())?;
        let continent = item.info.continent.and_then(|c| c.code).unwrap_or("");
        let country = item.info.country.and_then(|c| c.iso_code).unwrap_or("");
        let city = match item.info.city.and_then(|c| c.names) {
            Some(names) => names.get("en").unwrap_or(&""),
            None => "",
        };
        if !city.is_empty() {
            println!("{} {}-{}-{}", item.ip_net, continent, country, city);
        } else if !country.is_empty() {
            println!("{} {}-{}", item.ip_net, continent, country);
        } else if !continent.is_empty() {
            println!("{} {}", item.ip_net, continent);
        }
        n += 1;
    }
    eprintln!("processed {n} items");

    Ok(())
}
