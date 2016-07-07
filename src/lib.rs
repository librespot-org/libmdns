extern crate dns_parser;
#[macro_use] extern crate log;
extern crate net2;
extern crate mio;
extern crate rotor;
extern crate libc;
extern crate rand;
extern crate multimap;
extern crate nix;
extern crate byteorder;

mod fsm;
use fsm::{AddressFamily, FSM, Command, DEFAULT_TTL};

mod services;
use services::{Services, SharedServices, ServiceData};
mod net;

use std::sync::mpsc::Sender;
use std::io;
use std::thread;
use dns_parser::Name;
use std::sync::{Arc, Mutex, RwLock};

pub struct Responder {
    handle: Option<thread::JoinHandle<()>>,
    services: SharedServices,
    txs_notifiers: Vec<(Sender<Command>, rotor::Notifier)>,
}

pub struct Service<'a> {
    responder: &'a Responder,
    id: usize,
}

impl Responder {
    pub fn new() -> io::Result<Responder> {
        let txs_notifiers = Arc::new(Mutex::new(Vec::with_capacity(2)));

        let mut hostname = try!(net::gethostname());
        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }
        let services = Arc::new(RwLock::new(Services::new(hostname)));

        let mut config = rotor::Config::new();
        config.slab_capacity(32);
        config.mio().notify_capacity(32);

        let mut loop_ = rotor::Loop::new(&config).unwrap();
        {
            let (fsm, tx) = try!(FSM::new(AddressFamily::Inet, &services));
            let txs_notifiers = txs_notifiers.clone();
            loop_.add_machine_with(move |scope| {
                fsm.register(scope).unwrap();
                txs_notifiers.lock().unwrap()
                    .push((tx, scope.notifier()));
                rotor::Response::ok(fsm)
            }).unwrap();
        }
        {
            let (fsm, tx) = try!(FSM::new(AddressFamily::Inet6, &services));
            let txs_notifiers = txs_notifiers.clone();
            loop_.add_machine_with(move |scope| {
                fsm.register(scope).unwrap();
                txs_notifiers.lock().unwrap()
                    .push((tx, scope.notifier()));
                rotor::Response::ok(fsm)
            }).unwrap();
        }

        let handle = try!(thread::Builder::new().name("mdns-responder".to_owned()).spawn(move || {
            loop_.run(()).unwrap();
        }));

        Ok(Responder {
            handle: Some(handle),
            services: services,
            txs_notifiers: Arc::try_unwrap(txs_notifiers).unwrap()
                .into_inner().unwrap()
        })
    }

    pub fn register(&self, svc_type: String, svc_name: String, port: u16, txt: &[&str]) -> Service {
        let txt = if txt.is_empty() {
            vec![0]
        } else {
            txt.into_iter().flat_map(|entry| {
                let entry = entry.as_bytes();
                if entry.len() > 255 {
                    panic!("{:?} is too long for a TXT record", entry);
                }
                std::iter::once(entry.len() as u8).chain(entry.into_iter().cloned())
            }).collect()
        };

        let svc = ServiceData {
            typ: Name::from_str(format!("{}.local", svc_type)).unwrap(),
            name: Name::from_str(format!("{}.{}.local", svc_name, svc_type)).unwrap(),
            port: port,
            txt: txt,
        };
        self.send_unsolicited(svc.clone(), DEFAULT_TTL, true);

        let id = self.services
            .write().unwrap()
            .register(svc);

        Service {
            responder: self,
            id: id,
        }
    }

    fn send_unsolicited(&self, svc: ServiceData, ttl: u32, include_ip: bool) {
        self.send(Command::SendUnsolicited {
            svc: svc,
            ttl: ttl,
            include_ip: include_ip,
        });
    }

    fn send(&self, cmd: Command) {
        for &(ref tx, ref notifier) in self.txs_notifiers.iter() {
            tx.send(cmd.clone()).expect("responder died");
            notifier.wakeup().unwrap();
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.send(Command::Shutdown);
        self.handle.take().map(|h| h.join());
    }
}

impl <'a> Drop for Service<'a> {
    fn drop(&mut self) {
        let svc = self.responder.services
            .write().unwrap()
            .unregister(self.id);
        self.responder.send_unsolicited(svc, 0, false);
    }
}
