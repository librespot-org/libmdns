use env_logger;
use libmdns;

#[tokio::main]
pub async fn main() {
    env_logger::init();

    let responder = libmdns::Responder::builder()
        .use_v6(false)
        .build()
        .unwrap();

    let _svc = responder.register(
        "_http._tcp".to_owned(),
        "libmdns Web Server".to_owned(),
        80,
        &["path=/"],
    );

    tokio::signal::ctrl_c().await.unwrap();
}
