pub fn main() {
    let mut builder = env_logger::Builder::new();
    builder.parse_filters("libmdns=debug");
    builder.init();

    let responder = libmdns::Responder::new();
    let _svc = responder.register("_http._tcp", "libmdns Web Server", 80, &["path=/"]);

    loop {
        ::std::thread::sleep(::std::time::Duration::from_secs(10));
    }
}
