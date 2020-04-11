# libmdns - Rust mDNS responder

libmdns is a pure rust implementation of the mDNS ([RFC 6762]) and DNS-SD ([RFC 6763]) protocols.

[RFC 6762]: https://tools.ietf.org/html/rfc6762
[RFC 6763]: https://tools.ietf.org/html/rfc6763

## Usage

To use it, first add this to your `Cargo.toml`:

```toml
[dependencies]
libmdns = "0.2"
```

Only the latest stable version of rust and cargo are officially supported for now.
Please open an issue on GitHub if you need support for older versions.

## Provenance Note
This project originally started as a fork of [plietar/rust-mdns](https://github.com/plietar/rust-mdns).
