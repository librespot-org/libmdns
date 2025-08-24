use crate::dns_parser::{Name, RRData};
use multimap::MultiMap;
use rand::{rng, Rng};
use std::collections::HashMap;
use std::slice;
use std::sync::{Arc, RwLock};

/// A collection of registered services is shared between threads.
pub type Services = Arc<RwLock<ServicesInner>>;

pub struct ServicesInner {
    hostname: Name<'static>,
    /// main index
    by_id: HashMap<usize, ServiceData>,
    /// maps to id
    by_type: MultiMap<Name<'static>, usize>,
    /// maps to id
    by_name: HashMap<Name<'static>, usize>,
}

impl ServicesInner {
    pub fn new(hostname: String) -> Self {
        ServicesInner {
            hostname: Name::from_str(hostname),
            by_id: HashMap::new(),
            by_type: MultiMap::new(),
            by_name: HashMap::new(),
        }
    }

    pub fn get_hostname(&self) -> &Name<'static> {
        &self.hostname
    }

    pub fn find_by_name<'a>(&'a self, name: &'a Name<'a>) -> Option<&'a ServiceData> {
        self.by_name.get(name).and_then(|id| self.by_id.get(id))
    }

    pub fn find_by_type<'a>(&'a self, ty: &'a Name<'a>) -> FindByType<'a> {
        let ids = self.by_type.get_vec(ty).map(|ids| ids.iter());

        FindByType {
            services: self,
            ids,
        }
    }

    pub fn register(&mut self, svc: ServiceData) -> usize {
        let random_usize = || rng().random_range(..=usize::MAX);
        let mut id = random_usize();
        while self.by_id.contains_key(&id) {
            id = random_usize();
        }

        self.by_type.insert(svc.typ.clone(), id);
        self.by_name.insert(svc.name.clone(), id);
        self.by_id.insert(id, svc);

        id
    }

    pub fn unregister(&mut self, id: usize) -> ServiceData {
        use std::collections::hash_map::Entry;

        let svc = self.by_id.remove(&id).expect("unknown service");

        if let Some(entries) = self.by_type.get_vec_mut(&svc.typ) {
            entries.retain(|&e| e != id);
        }

        match self.by_name.entry(svc.name.clone()) {
            Entry::Occupied(entry) => {
                assert_eq!(*entry.get(), id);
                entry.remove();
            }
            Entry::Vacant(_) => {
                panic!("unknown/wrong service for id {}", id);
            }
        }

        svc
    }

    pub fn all_types(&self) -> impl Iterator<Item = &Name<'static>> {
        self.by_type.keys()
    }
}

impl<'a> IntoIterator for &'a ServicesInner {
    type Item = &'a crate::ServiceData;
    type IntoIter = std::collections::hash_map::Values<'a, usize, crate::ServiceData>;

    fn into_iter(self) -> Self::IntoIter {
        self.by_id.values()
    }
}

/// Returned by [`ServicesInner.find_by_type`](struct.ServicesInner.html#method.find_by_type)
pub struct FindByType<'a> {
    services: &'a ServicesInner,
    ids: Option<slice::Iter<'a, usize>>,
}

impl<'a> Iterator for FindByType<'a> {
    type Item = &'a ServiceData;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.as_mut().and_then(Iterator::next).map(|id| {
            let svc = self.services.by_id.get(id);
            svc.expect("missing service")
        })
    }
}

#[derive(Clone, Debug)]
pub struct ServiceData {
    pub name: Name<'static>,
    pub typ: Name<'static>,
    pub port: u16,
    pub txt: Vec<u8>,
}

/// Packet building helpers for `fsm` to respond with `ServiceData`
impl ServiceData {
    pub fn ptr_rr(&self) -> RRData<'_> {
        RRData::PTR(self.name.clone())
    }

    pub fn srv_rr<'a>(&self, hostname: &'a Name<'_>) -> RRData<'a> {
        RRData::SRV {
            priority: 0,
            weight: 0,
            port: self.port,
            target: hostname.clone(),
        }
    }

    pub fn txt_rr(&self) -> RRData<'_> {
        RRData::TXT(&self.txt)
    }
}
