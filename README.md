# rust-mdns - Rust mDNS responder

rust-mdns is a pure rust implementation of the mDNS ([RFC 6762]) and DNS-SD ([RFC 6763]) protocols.

## Usage

To use it, first add this to your `Cargo.toml`:

```toml
[dependencies.mdns]
git = "https://github.com/plietar/rust-mdns"
```

Then, add this to your crate root:

```rust
extern crate mdns;
```

[RFC 6762]: https://tools.ietf.org/html/rfc6762
[RFC 6763]: https://tools.ietf.org/html/rfc6763

## Provenance Note
This project originally started as a fork of [plietar/rust-mdns](https://github.com/plietar/rust-mdns).
