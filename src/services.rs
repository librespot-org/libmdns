use crate::dns_parser::{self, Name, QueryClass, RRData};
use multimap::MultiMap;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::slice;
use std::sync::{Arc, RwLock};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

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
            hostname: Name::from_str(hostname).unwrap(),
            by_id: HashMap::new(),
            by_type: MultiMap::new(),
            by_name: HashMap::new(),
        }
    }

    pub fn get_hostname(&self) -> &Name<'static> {
        &self.hostname
    }

    pub fn find_by_name<'a>(&'a self, name: &'a Name<'a>) -> Option<&ServiceData> {
        self.by_name.get(name).and_then(|id| self.by_id.get(id))
    }

    pub fn find_by_type<'a>(&'a self, ty: &'a Name<'a>) -> FindByType<'a> {
        let ids = self.by_type.get_vec(ty).map(|ids| ids.iter());

        FindByType {
            services: self,
            ids: ids,
        }
    }

    pub fn register(&mut self, svc: ServiceData) -> usize {
        let mut id = thread_rng().gen::<usize>();
        while self.by_id.contains_key(&id) {
            id = thread_rng().gen::<usize>();
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
            _ => {
                panic!("unknown/wrong service for id {}", id);
            }
        }

        svc
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
    pub fn add_ptr_rr(&self, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(
            &self.typ,
            QueryClass::IN,
            ttl,
            &RRData::PTR(self.name.clone()),
        )
    }

    pub fn add_srv_rr(&self, hostname: &Name, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(
            &self.name,
            QueryClass::IN,
            ttl,
            &RRData::SRV {
                priority: 0,
                weight: 0,
                port: self.port,
                target: hostname.clone(),
            },
        )
    }

    pub fn add_txt_rr(&self, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(&self.name, QueryClass::IN, ttl, &RRData::TXT(&self.txt))
    }
}
