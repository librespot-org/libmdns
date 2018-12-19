use net2::UdpBuilder;
#[cfg(not(windows))]
use net2::unix::UnixUdpBuilderExt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use super::MDNS_PORT;

pub enum Inet {}
pub enum Inet6 {}

pub trait AddressFamily {
    fn bind() -> io::Result<UdpSocket> {
        let addr = SocketAddr::new(Self::any_addr(), MDNS_PORT);
        let builder = Self::socket_builder()?;
        builder.reuse_address(true)?;
        #[cfg(not(windows))]
        let _ = builder.reuse_port(true);
        let socket = builder.bind(&addr)?;
        Self::join_multicast(&socket)?;
        Ok(socket)
    }

    fn socket_builder() -> io::Result<UdpBuilder>;
    fn any_addr() -> IpAddr;
    fn mdns_group() -> IpAddr;
    fn join_multicast(socket: &UdpSocket) -> io::Result<()>;
    fn v6() -> bool;
}

impl AddressFamily for Inet {
    fn socket_builder() -> io::Result<UdpBuilder> {
        UdpBuilder::new_v4()
    }
    fn any_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(0,0,0,0))
    }
    fn mdns_group() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(224,0,0,251))
    }
    fn join_multicast(socket: &UdpSocket) -> io::Result<()> {
        socket.join_multicast_v4(
            &Ipv4Addr::new(224,0,0,251),
            &Ipv4Addr::new(0,0,0,0),
        )
    }
    fn v6() -> bool {
        false
    }
}

impl AddressFamily for Inet6 {
    fn socket_builder() -> io::Result<UdpBuilder> {
        UdpBuilder::new_v6()
    }
    fn any_addr() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,0))
    }
    fn mdns_group() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xff02,0,0,0,0,0,0,0xfb))
    }
    fn join_multicast(socket: &UdpSocket) -> io::Result<()> {
        socket.join_multicast_v6(
            &Ipv6Addr::new(0xff02,0,0,0,0,0,0,0xfb),
            0
        )
    }
    fn v6() -> bool {
        true
    }
}
