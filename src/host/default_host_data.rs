use crate::dns_parser::Name;
use crate::host::HostData;
use if_addrs::get_if_addrs;
use std::net::IpAddr;
use std::sync::Arc;
#[derive(Debug)]
pub struct DefaultHostData {
    hostname: Name<'static>,
}

lazy_static! {
    static ref DEFAULT_HOST_DATA_INSTANCE: Option<Arc<DefaultHostData>> =
        DefaultHostData::raw_get();
}

impl DefaultHostData {
    pub fn get() -> Option<Arc<Self>> {
        match DEFAULT_HOST_DATA_INSTANCE.as_ref() {
            Some(instance) => Some(instance.clone()),
            None => None,
        }
    }
    fn raw_get() -> Option<Arc<Self>> {
        let mut hostname = hostname::get().ok()?.into_string().ok()?;

        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        Some(Arc::new(Self {
            hostname: Name::from_str(hostname).ok()?,
        }))
    }
}

impl HostData for DefaultHostData {
    fn get_hostname(&self) -> &Name<'static> {
        &self.hostname
    }
    fn get_ips(&self) -> std::io::Result<Vec<IpAddr>> {
        let interfaces = get_if_addrs()?;
        Ok(interfaces
            .into_iter()
            .filter(|x| !x.is_loopback())
            .map(|x| x.ip())
            .collect())
    }
}
