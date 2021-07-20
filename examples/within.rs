use ipnetwork::IpNetwork;

use maxminddb::geoip2;
use maxminddb::Within;

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let reader = maxminddb::Reader::open_readfile(
        args.next()
            .ok_or("First argument must be the path to the IP database")?,
    )
    .unwrap();
    let cidr: String = args
        .next()
        .ok_or("Second argument must be the IP address and mask in CIDR notation")?
        .parse()
        .unwrap();
    let ip_net = if cidr.contains(":") {
        IpNetwork::V6(cidr.parse().unwrap())
    } else {
        IpNetwork::V4(cidr.parse().unwrap())
    };
    // TODO: is there a way to omit the _, it should be discernable from the reader
    let within: Within<geoip2::City, _> = reader.within(ip_net).unwrap();
    for item in within {
        println!("item={:#?}", item);
    }
    Ok(())
}
