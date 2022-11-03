use super::MDNS_PORT;
use if_addrs::get_if_addrs;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

#[cfg(not(windows))]
use nix::net::if_::if_nametoindex;

#[cfg(windows)]
use win::if_nametoindex;

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
        let addresses = get_address_list()?;
        if addresses.is_empty() {
            socket.join_multicast_v4(multiaddr, &Ipv4Addr::UNSPECIFIED)
        } else {
            for (_, address) in addresses {
                if let IpAddr::V4(ip) = address {
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
        let addresses = get_address_list()?;
        if addresses.is_empty() {
            socket.join_multicast_v6(multiaddr, 0)
        } else {
            for (iface_name, address) in addresses {
                if let IpAddr::V6(_) = address {
                    let ipv6_index = if_nametoindex(iface_name.as_str()).unwrap_or(0);
                    if ipv6_index != 0 {
                        socket.join_multicast_v6(multiaddr, ipv6_index)?;
                    }
                }
            }
            Ok(())
        }
    }
}

fn get_address_list() -> io::Result<Vec<(String, IpAddr)>> {
    Ok(get_if_addrs()?
        .iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| (iface.name.clone(), iface.ip()))
        .collect())
}

#[cfg(windows)]
mod win
{
    use std::ffi::{CString, NulError};

    mod private {
        use std::ffi::{c_char, c_uint};

        #[link(name = "Iphlpapi")]
        extern "C" {
            pub fn if_nametoindex(ifname: *const c_char) -> c_uint;
        }
    }

    pub fn if_nametoindex(ifname: &str) -> Result<u32, NulError> {
        let c_str = CString::new(ifname)?;
        Ok(unsafe { private::if_nametoindex(c_str.as_ptr()) })
    }
}
