use crate::dns_parser::Name;
use crate::host::HostData;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct FixedHostData {
    hostname: Name<'static>,
    ips: Vec<IpAddr>,
}

impl FixedHostData {
    pub fn new(hostname: String, ips: Vec<IpAddr>) -> Arc<Self> {
        Arc::new(Self {
            hostname: Name::from_str(hostname).unwrap(),
            ips,
        })
    }
}

impl HostData for FixedHostData {
    fn get_hostname(&self) -> &Name<'static> {
        &self.hostname
    }
    fn get_ips(&self) -> std::io::Result<Vec<IpAddr>> {
        Ok(self.ips.clone())
    }
}
