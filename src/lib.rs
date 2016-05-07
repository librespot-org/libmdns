extern crate dns_parser;
#[macro_use] extern crate log;
extern crate net2;
extern crate mio;
extern crate rotor;
extern crate libc;
extern crate eventual;
extern crate rand;
extern crate multimap;
extern crate nix;
extern crate byteorder;

mod fsm;
use fsm::{FSM, Command, ServiceData};

mod net;

use std::sync::mpsc::Sender;
use std::io;
use std::thread;
use eventual::{Async, Future};
use dns_parser::Name;

pub struct Responder {
    handle: Option<thread::JoinHandle<()>>,
    tx: Sender<Command>,
    notifier: rotor::Notifier,
}

pub struct Service<'a> {
    responder: &'a Responder,
    id: usize,
}

impl Responder {
    pub fn new() -> io::Result<Responder> {
        let (fsm, tx) = try!(FSM::new());

        let mut config = rotor::Config::new();
        config.slab_capacity(32);
        config.mio().notify_capacity(32);

        let mut notifier = None;
        let mut loop_ = rotor::Loop::new(&config).unwrap();
        {
            let notifier = &mut notifier;

            loop_.add_machine_with(move |scope| {
                fsm.register(scope).unwrap();
                *notifier = Some(scope.notifier());
                rotor::Response::ok(fsm)
            }).unwrap();
        }

        let handle = try!(thread::Builder::new().name("mdns-responder".to_owned()).spawn(move || {
            loop_.run(()).unwrap();
        }));

        Ok(Responder {
            handle: Some(handle),
            tx: tx,
            notifier: notifier.unwrap(),
        })
    }

    pub fn register(&self, svc_type: String, svc_name: String, port: u16, txt: &[&str]) -> Service {
        let (complete, future) = Future::pair();

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

        self.send(Command::Register(svc, complete));

        let id = future.await().unwrap();
        Service {
            responder: self,
            id: id,
        }
    }

    fn send(&self, cmd: Command) {
        self.tx.send(cmd).expect("responder died");
        self.notifier.wakeup().unwrap();
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
        self.responder.send(Command::Unregister(self.id));
    }
}
