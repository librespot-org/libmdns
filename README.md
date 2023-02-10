# libmdns - Rust mDNS responder

libmdns is a pure rust implementation of the mDNS ([RFC 6762]) and DNS-SD ([RFC 6763]) protocols. This means that in response to UDP broadcasted DNS requests on port 5353, libmdns will broadcast a DNS response advertising the services you register.

Built with the tokio async runtime, libmdns can run in a dedicated thread, or be spawned with an existing tokio Handle.

[RFC 6762]: https://tools.ietf.org/html/rfc6762
[RFC 6763]: https://tools.ietf.org/html/rfc6763

## Usage

To use it, add this to your `Cargo.toml`:

```toml
[dependencies]
libmdns = "0.7"
```

See the [example](https://github.com/librespot-org/libmdns/blob/stable-0.7.x/examples/register.rs) for use within code.

## Dependencies

libmdns' oldest supported Rust toolchain is `1.46.0`, _however it may compile fine on older versions of rust._

**We hold no strong garantees for sticking to a Minimum Supported Rust Version**. Please open an issue on GitHub if you need support for older compilers or different platforms.

libmdns is built with the help of the [tokio](https://github.com/tokio-rs/tokio) 1.0 runtime.

## Provenance Note

This project originally started as a fork of [plietar/rust-mdns](https://github.com/plietar/rust-mdns).

## Contributing

Thankyou for considering contributing, any and all contributions are happily welcomed!

On the whole this library works. There is no-one actively seeking to improve it for it's own sake, and issues may not be immediately fixed. However if you're willing to open a Pull Request with changes to improve this project for your own uses in a way that doesn't sacrifice existing platform and feature support, I'll do my best to review, merge and release.
