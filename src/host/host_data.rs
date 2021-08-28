use std::fmt::Debug;
use crate::dns_parser::Name;
use std::net::IpAddr;

pub trait HostData : Debug {
    fn get_hostname(&self) -> &Name<'static>;
    fn get_ips(&self) -> std::io::Result<Vec<IpAddr>>;
}
