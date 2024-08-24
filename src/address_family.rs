use super::MDNS_PORT;
use if_addrs::{get_if_addrs, Interface};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashSet;
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

        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
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
        let ifaces = get_iface_list()?;
        if ifaces.is_empty() {
            socket.join_multicast_v4(multiaddr, &Ipv4Addr::UNSPECIFIED)
        } else {
            for iface in ifaces {
                if let IpAddr::V4(ip) = iface.ip() {
                    socket.join_multicast_v4(multiaddr, &ip)?;
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
        let ifaces = get_iface_list()?;
        if ifaces.is_empty() {
            socket.join_multicast_v6(multiaddr, 0)
        } else {
            // TODO: Make each interface resilient to failures on another.
            for iface in ifaces {
                if let (IpAddr::V6(_), Some(ipv6_index)) = (iface.ip(), iface.index) {
                    socket.join_multicast_v6(multiaddr, ipv6_index)?;
                }
            }
            Ok(())
        }
    }
}

fn get_iface_list() -> io::Result<Vec<Interface>> {
    // There may be multiple ip addresses on a single interface and we join multicast by interface.
    // Joining multicast on the same interface multiple times returns an error
    // so we filter duplicate interfaces.
    let mut collected_interfaces = HashSet::new();
    Ok(get_if_addrs()?
        .into_iter()
        .filter(|iface| !iface.is_loopback() && collected_interfaces.insert(iface.name.clone()))
        .collect())
}
