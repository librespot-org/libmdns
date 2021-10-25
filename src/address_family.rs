use super::MDNS_PORT;
use if_addrs::get_if_addrs;
use nix::net::if_::if_nametoindex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

pub enum Inet {}

pub enum Inet6 {}

pub trait AddressFamily {
    type Addr: Into<IpAddr>;

    const ANY_ADDR: Self::Addr;
    const MDNS_GROUP: Self::Addr;

    const DOMAIN: Domain;

    fn join_multicast(socket: &Socket, multiaddr: &Self::Addr) -> io::Result<()>;

    fn udp_socket() -> io::Result<Socket> {
        Socket::new(Self::DOMAIN, Type::DGRAM, Some(Protocol::UDP))
    }

    fn bind() -> io::Result<UdpSocket> {
        let addr: SockAddr = SocketAddr::new(Self::ANY_ADDR.into(), MDNS_PORT).into();
        let socket = Self::udp_socket()?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;

        #[cfg(not(windows))]
        #[cfg(not(target_os = "illumos"))]
        socket.set_reuse_port(true)?;

        socket.bind(&addr)?;
        Self::join_multicast(&socket, &Self::MDNS_GROUP)?;
        Ok(socket.into())
    }
}

impl AddressFamily for Inet {
    type Addr = Ipv4Addr;

    const ANY_ADDR: Self::Addr = Ipv4Addr::UNSPECIFIED;
    const MDNS_GROUP: Self::Addr = Ipv4Addr::new(224, 0, 0, 251);

    const DOMAIN: Domain = Domain::IPV4;

    fn join_multicast(socket: &Socket, multiaddr: &Self::Addr) -> io::Result<()> {
        let interfaces = get_if_addrs()?;
        if interfaces.is_empty() {
            socket.join_multicast_v4(multiaddr, &Ipv4Addr::UNSPECIFIED)
        } else {
            for iface in interfaces {
                if iface.is_loopback() {
                    continue;
                }
                match (iface.ip(), Self::DOMAIN) {
                    (IpAddr::V4(ip), Domain::IPV4) => {
                        socket.join_multicast_v4(multiaddr, &ip)?;
                    }
                    _ => (),
                }
            }
            Ok(())
        }
    }
}

impl AddressFamily for Inet6 {
    type Addr = Ipv6Addr;

    const ANY_ADDR: Self::Addr = Ipv6Addr::UNSPECIFIED;
    const MDNS_GROUP: Self::Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

    const DOMAIN: Domain = Domain::IPV6;

    fn join_multicast(socket: &Socket, multiaddr: &Self::Addr) -> io::Result<()> {
        let interfaces = get_if_addrs()?;
        if interfaces.is_empty() {
            socket.join_multicast_v6(multiaddr, 0)
        } else {
            for iface in interfaces {
                if iface.is_loopback() {
                    continue;
                }
                match (iface.ip(), Self::DOMAIN) {
                    (IpAddr::V6(ip), Domain::IPV6) => {
                        socket
                            .join_multicast_v6(multiaddr, if_nametoindex(iface.name.as_str())?)?;
                    }
                    _ => (),
                }
            }
            Ok(())
        }
    }
}
