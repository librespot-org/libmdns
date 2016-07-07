use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use multimap::MultiMap;
use rand::{Rng, thread_rng};
use dns_parser::{self, QueryClass, Name, RRData};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;


pub type Services = Arc<RwLock<ServicesInner>>;

pub struct ServicesInner {
    pub hostname: Name<'static>,
    /// main index
    pub by_id: HashMap<usize, ServiceData>,
    /// maps to id
    pub by_type: MultiMap<Name<'static>, usize>,
    /// maps to id
    pub by_name: HashMap<Name<'static>, usize>
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
            entries.retain(|&e| e == id);
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

#[derive(Clone)]
pub struct ServiceData {
    pub name: Name<'static>,
    pub typ: Name<'static>,
    pub port: u16,
    pub txt: Vec<u8>,
}

impl ServiceData {
    pub fn add_ptr_rr(&self, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(&self.typ, QueryClass::IN, ttl, &RRData::PTR(self.name.clone()))
    }

    pub fn add_srv_rr(&self, hostname: &Name, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(&self.name, QueryClass::IN, ttl, &RRData::SRV {
            priority: 0,
            weight: 0,
            port: self.port,
            target: hostname.clone(),
        })
    }

    pub fn add_txt_rr(&self, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(&self.name, QueryClass::IN, ttl, &RRData::TXT(&self.txt))
    }
}
