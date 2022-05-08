pub fn main() {
    let mut builder = env_logger::Builder::new();
    builder.parse_filters("libmdns=debug");
    builder.init();

    // allow only these two IP address to be sent in A record
    let vec: Vec<std::net::IpAddr> = vec![
        "192.168.1.10".parse::<std::net::Ipv4Addr>().unwrap().into(),
        std::net::Ipv6Addr::new(0, 0, 0, 0xfe80, 0x1ff, 0xfe23, 0x4567, 0x890a).into(),
    ];

    let responder = libmdns::Responder::new_with_ip_list(vec).unwrap();
    let _svc = responder.register(
        "_http._tcp".to_owned(),
        "libmdns Web Server".to_owned(),
        80,
        &["path=/"],
    );

    loop {
        ::std::thread::sleep(::std::time::Duration::from_secs(10));
    }
}
