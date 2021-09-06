# libmdns - Rust mDNS responder

libmdns is a pure rust implementation of the mDNS ([RFC 6762]) and DNS-SD ([RFC 6763]) protocols. This means that libmdns will respond to LAN DNS requests broadcasted on port 5353 with a broadcast of it's own, advertising the services you register.

Built with the tokio async runtime, libmdns can run in a dedicated thread, or be spawned with an existing tokio Handle.

[RFC 6762]: https://tools.ietf.org/html/rfc6762
[RFC 6763]: https://tools.ietf.org/html/rfc6763

## Usage

To use it, add this to your `Cargo.toml`:

```toml
[dependencies]
libmdns = "0.6"
```

See the [example](https://github.com/librespot-org/libmdns/blob/stable-0.6.x/examples/register.rs) for use within code.

## Dependencies

**We hold no strong garantees of MSRV**. However we strive to support the oldest practical compiler version for our current dependencies.

Please open an issue on GitHub if you need support for older compilers or different platforms.

libmdns is built with the help of the [tokio](https://github.com/tokio-rs/tokio) runtime.

Current stable:
* `libmdns 0.6.x` (`tokio=1.x`, currently tested with `rustc>=1.46.0`)

Maintenance mode:
* `libmdns 0.2.x` (`tokio-core=0.1`, `rustc>=1.40.0`, used actively by librespot)

Unsupported:
* `libmdns 0.5.x` (`tokio=0.3`, currently tested with `rustc>=1.45.2`)
* `libmdns 0.4.3` (`tokio=0.2`, currently tested with `rustc>=1.40.0`)
* `libmdns 0.3.x` (`tokio=0.1`, currently tested with `rustc>=1.40.0`)

_May compile fine on older versions of rust, but the minimum CI-tested version is listed as above._

## Provenance Note
This project originally started as a fork of [plietar/rust-mdns](https://github.com/plietar/rust-mdns).
