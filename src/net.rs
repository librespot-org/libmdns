use libc::{self, c_char, c_int, c_uint, size_t};
use std::io;
use std::os::unix::io::AsRawFd;
use std::mem;
use std::ptr::null_mut;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use byteorder::{BigEndian, ByteOrder};

pub fn gethostname() -> io::Result<String> {
    unsafe {
        let mut name = Vec::new();
        name.resize(65, 0u8);

        let ptr = name.as_mut_ptr() as *mut c_char;
        let cap = name.len() as size_t;

        let ret = libc::gethostname(ptr, cap);
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let len = name.iter().position(|byte| *byte == 0).unwrap_or(cap);
        name.resize(len, 0);

        Ok(String::from_utf8_lossy(&name).into_owned())
    }
}

pub fn set_socket_opt<T, S: AsRawFd>(s: &S, optname: c_int, val: &T) {
    let fd = s.as_raw_fd();
    let ptr = val as *const T as *const libc::c_void;
    let size = mem::size_of::<T>() as libc::socklen_t;

    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, optname, ptr, size);
    }
}

pub fn set_reuse_addr<T: AsRawFd>(s: &T, val: bool) {
    set_socket_opt(s, libc::SO_REUSEADDR, &(val as libc::c_int));
}

pub fn set_reuse_port<T: AsRawFd>(s: &T, val: bool) {
    set_socket_opt(s, libc::SO_REUSEPORT, &(val as libc::c_int));
}

pub struct GetIfAddrs(*mut libc::ifaddrs, *mut libc::ifaddrs);

pub fn getifaddrs() -> GetIfAddrs {
    let mut ptr = null_mut();
    unsafe {
        libc::getifaddrs(&mut ptr as *mut *mut libc::ifaddrs);
    }

    GetIfAddrs(ptr, ptr)
}

impl Iterator for GetIfAddrs {
    type Item = Interface;

    fn next(&mut self) -> Option<Self::Item> {
        if self.1.is_null() {
            return None
        } else {
            unsafe {
                let iface = Interface::new(&*self.1);
                self.1 = (*self.1).ifa_next;
                Some(iface)
            }
        }
    }
}

impl Drop for GetIfAddrs {
    fn drop(&mut self) {
        unsafe {
            libc::freeifaddrs(self.0);
        }
    }
}

pub struct Interface {
    addr: Option<SocketAddr>,
    flags: c_uint,
}

impl Interface {
    fn new(ifa: &libc::ifaddrs) -> Interface {
        let addr = unsafe {
            if ifa.ifa_addr.is_null() {
                None
            } else {
                match (*ifa.ifa_addr).sa_family as c_int {
                    libc::AF_INET => {
                        let sa = *(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = IpAddr::V4(u32::from_be(sa.sin_addr.s_addr).into());
                        let port = u16::from_be(sa.sin_port);
                        Some(SocketAddr::new(ip, port))
                    }
                    libc::AF_INET6 => {
                        let sa = *(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let addr = sa.sin6_addr.s6_addr;
                        let ip = IpAddr::V6(Ipv6Addr::new(BigEndian::read_u16(&addr[0..2]),
                                                          BigEndian::read_u16(&addr[2..4]),
                                                          BigEndian::read_u16(&addr[4..6]),
                                                          BigEndian::read_u16(&addr[6..8]),
                                                          BigEndian::read_u16(&addr[8..10]),
                                                          BigEndian::read_u16(&addr[10..12]),
                                                          BigEndian::read_u16(&addr[12..14]),
                                                          BigEndian::read_u16(&addr[14..16])));
                        let port = u16::from_be(sa.sin6_port);
                        Some(SocketAddr::new(ip, port))
                    }
                    _ => None,
                }
            }
        };

        Interface {
            addr: addr,
            flags: ifa.ifa_flags,
        }
    }

    #[allow(dead_code)]
    pub fn addr(&self) -> Option<SocketAddr> {
        self.addr
    }

    pub fn ip(&self) -> Option<IpAddr> {
        self.addr.map(|a| a.ip())
    }

    pub fn is_loopback(&self) -> bool {
        (self.flags as c_int & libc::IFF_LOOPBACK) == libc::IFF_LOOPBACK
    }
}
