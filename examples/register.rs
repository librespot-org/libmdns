extern crate env_logger;
extern crate libmdns;

pub fn main() {
    env_logger::init();

    let responder = libmdns::Responder::new().unwrap();
    let _svc = responder.register(
        "_http._tcp".to_owned(),
        "Web Server".to_owned(),
        80,
        &["path=/"]);

    loop {
        ::std::thread::sleep(::std::time::Duration::from_secs(10));
    }
}
