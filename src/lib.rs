#[macro_use(quick_error)]
extern crate quick_error;

#[macro_use]
extern crate log;

extern crate byteorder;
extern crate futures;
extern crate get_if_addrs;
extern crate hostname;
extern crate multimap;
extern crate net2;
extern crate rand;
extern crate tokio;

use futures::channel::mpsc;
use futures::future::{BoxFuture, FutureExt};
use std::cell::RefCell;
use std::io;
use std::sync::{Arc, RwLock};

mod dns_parser;
use crate::dns_parser::Name;

mod address_family;
mod fsm;
mod services;

use crate::address_family::{Inet, Inet6};
use crate::fsm::{Command, FSM};
use crate::services::{ServiceData, Services, ServicesInner};

const DEFAULT_TTL: u32 = 60;
const MDNS_PORT: u16 = 5353;

pub struct ResponderBuilder {
    v4: bool,
    v6: bool,
}

impl ResponderBuilder {
    pub fn new() -> Self {
        ResponderBuilder { v4: true, v6: true }
    }

    pub fn use_v6(mut self, use_v6: bool) -> Self {
        self.v6 = use_v6;
        self
    }

    pub fn use_v4(mut self, use_v4: bool) -> Self {
        self.v4 = use_v4;
        self
    }

    pub fn build(self) -> io::Result<Responder> {
        Responder::start(self)
    }
}

pub struct Responder {
    services: Services,
    commands: RefCell<CommandSender>,
    shutdown: Arc<Shutdown>,
}

pub struct Service {
    id: usize,
    services: Services,
    commands: CommandSender,
    _shutdown: Arc<Shutdown>,
}

type ResponderTask = BoxFuture<'static, Result<(), io::Error>>;

impl Responder {
    pub fn new() -> io::Result<Responder> {
        Self::builder().build()
    }
    pub fn builder() -> ResponderBuilder {
        ResponderBuilder::new()
    }

    fn start(builder: ResponderBuilder) -> io::Result<Self> {
        let (responder, task) = Self::create_task(builder)?;

        tokio::spawn(task);

        Ok(responder)
    }

    fn create_task(builder: ResponderBuilder) -> io::Result<(Responder, ResponderTask)> {
        let mut hostname = match hostname::get() {
            Ok(s) => match s.into_string() {
                Ok(s) => s,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Hostname not valid unicode",
                    ))
                }
            },
            Err(err) => return Err(err),
        };
        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        let services = Arc::new(RwLock::new(ServicesInner::new(hostname)));

        let v4 = {
            if builder.v4 {
                Some(FSM::<Inet>::new(&services))
            } else {
                None
            }
        };

        let v6 = {
            if builder.v6 {
                Some(FSM::<Inet6>::new(&services))
            } else {
                None
            }
        };

        let (task, commands): (ResponderTask, _) = match (v4, v6) {
            (Some(Ok((v4_task, v4_command))), Some(Ok((v6_task, v6_command)))) => {
                let task = futures::future::join(v4_task, v6_task)
                    .map(|_| Ok(()))
                    .boxed();
                let commands = vec![v4_command, v6_command];
                (task, commands)
            }

            (Some(Ok((v4_task, v4_command))), Some(Err(err))) => {
                warn!("Failed to register IPv6 receiver: {:?}", err);
                (v4_task.boxed(), vec![v4_command])
            }

            (Some(Err(err)), Some(Ok((v6_task, v6_command)))) => {
                warn!("Failed to register IPv4 receiver: {:?}", err);
                (v6_task.boxed(), vec![v6_command])
            }

            (None, Some(Ok((v6_task, v6_command)))) => (v6_task.boxed(), vec![v6_command]),

            (Some(Ok((v4_task, v4_command))), None) => (v4_task.boxed(), vec![v4_command]),

            (_, Some(Err(err))) => return Err(err),
            (Some(Err(err)), _) => return Err(err),
            (None, None) => panic!("No v4 or v6 responder configured"),
        };

        let commands = CommandSender(commands);
        let responder = Responder {
            services,
            commands: RefCell::new(commands.clone()),
            shutdown: Arc::new(Shutdown(commands)),
        };

        Ok((responder, task))
    }
}

impl Responder {
    pub fn register(&self, svc_type: String, svc_name: String, port: u16, txt: &[&str]) -> Service {
        let txt = if txt.is_empty() {
            vec![0]
        } else {
            txt.iter()
                .flat_map(|entry| {
                    let entry = entry.as_bytes();
                    if entry.len() > 255 {
                        panic!("{:?} is too long for a TXT record", entry);
                    }
                    std::iter::once(entry.len() as u8).chain(entry.iter().cloned())
                })
                .collect()
        };

        let svc = ServiceData {
            typ: Name::from_str(format!("{}.local", svc_type)).unwrap(),
            name: Name::from_str(format!("{}.{}.local", svc_name, svc_type)).unwrap(),
            port,
            txt,
        };

        self.commands
            .borrow_mut()
            .send_unsolicited(svc.clone(), DEFAULT_TTL, true);

        let id = self.services.write().unwrap().register(svc);

        Service {
            id,
            commands: self.commands.borrow().clone(),
            services: self.services.clone(),
            _shutdown: self.shutdown.clone(),
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let svc = self.services.write().unwrap().unregister(self.id);
        self.commands.send_unsolicited(svc, 0, false);
    }
}

struct Shutdown(CommandSender);

impl Drop for Shutdown {
    fn drop(&mut self) {
        self.0.send_shutdown();
        // TODO wait for tasks to shutdown
    }
}

#[derive(Clone)]
struct CommandSender(Vec<mpsc::UnboundedSender<Command>>);
impl CommandSender {
    fn send(&mut self, cmd: Command) {
        for tx in self.0.iter_mut() {
            tx.unbounded_send(cmd.clone()).expect("responder died");
        }
    }

    fn send_unsolicited(&mut self, svc: ServiceData, ttl: u32, include_ip: bool) {
        self.send(Command::SendUnsolicited {
            svc,
            ttl,
            include_ip,
        });
    }

    fn send_shutdown(&mut self) {
        self.send(Command::Shutdown);
    }
}
