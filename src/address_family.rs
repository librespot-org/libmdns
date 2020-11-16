use super::MDNS_PORT;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

pub enum Inet {}
pub enum Inet6 {}

pub trait AddressFamily {
    fn bind() -> io::Result<UdpSocket> {
        let addr = SockAddr::from(SocketAddr::new(Self::any_addr(), MDNS_PORT));
        let socket = Self::socket_builder()?;
        socket.set_reuse_address(true)?;
        #[cfg(not(windows))]
        let _ = socket.set_reuse_port(true)?;
        socket.bind(&addr)?;
        Self::join_multicast(&socket)?;
        Ok(socket.into_udp_socket())
    }

    fn socket_builder() -> io::Result<Socket>;
    fn any_addr() -> IpAddr;
    fn mdns_group() -> IpAddr;
    fn join_multicast(socket: &Socket) -> io::Result<()>;
    fn v6() -> bool;
}

impl AddressFamily for Inet {
    fn socket_builder() -> io::Result<Socket> {
        Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))
    }
    fn any_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    }
    fn mdns_group() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))
    }
    fn join_multicast(socket: &Socket) -> io::Result<()> {
        socket.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::new(0, 0, 0, 0))
    }
    fn v6() -> bool {
        false
    }
}

impl AddressFamily for Inet6 {
    fn socket_builder() -> io::Result<Socket> {
        Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))
    }
    fn any_addr() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
    }
    fn mdns_group() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb))
    }
    fn join_multicast(socket: &Socket) -> io::Result<()> {
        socket.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 0)
    }
    fn v6() -> bool {
        true
    }
}
