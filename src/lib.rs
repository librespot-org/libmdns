use futures_util::{future, future::FutureExt};
use log::warn;
use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::marker::Unpin;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use std::thread;
use tokio::{runtime::Handle, sync::mpsc};

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

type ResponderTask = Box<dyn Future<Output = ()> + Send + Unpin>;

impl Responder {
    /// Spawn a `Responder` task on an new os thread.
    pub fn new() -> io::Result<Responder> {
        Self::new_with_ip_list(Vec::new())
    }
    /// Spawn a `Responder` task on an new os thread.
    /// DNS response records will have the reported IPs limited to those passed in here.
    /// This can be particularly useful on machines with lots of networks created by tools such as docker.
    pub fn new_with_ip_list(allowed_ips: Vec<IpAddr>) -> io::Result<Responder> {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        thread::Builder::new()
            .name("mdns-responder".to_owned())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    match Self::with_default_handle_and_ip_list(allowed_ips) {
                        Ok((responder, task)) => {
                            tx.send(Ok(responder)).expect("tx responder channel closed");
                            task.await;
                        }
                        Err(e) => tx.send(Err(e)).expect("tx responder channel closed"),
                    }
                })
            })?;
        rx.recv().expect("rx responder channel closed")
    }

    /// Spawn a `Responder` with the provided tokio `Handle`.
    ///
    /// # Example
    /// ```no_run
    /// use libmdns::Responder;
    ///
    /// # use std::io;
    /// # fn main() -> io::Result<()> {
    /// let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    /// let handle = rt.handle().clone();
    /// let responder = Responder::spawn(&handle)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn spawn(handle: &Handle) -> io::Result<Responder> {
        Self::spawn_with_ip_list(handle, Vec::new())
    }

    /// Spawn a `Responder` task  with the provided tokio `Handle`.
    /// DNS response records will have the reported IPs limited to those passed in here.
    /// This can be particularly useful on machines with lots of networks created by tools such as docker.
    pub fn spawn_with_ip_list(handle: &Handle, allowed_ips: Vec<IpAddr>) -> io::Result<Responder> {
        let (responder, task) = Self::with_default_handle_and_ip_list(allowed_ips)?;
        handle.spawn(task);
        Ok(responder)
    }

    /// Spawn a `Responder` on the default tokio handle.
    pub fn with_default_handle() -> io::Result<(Responder, ResponderTask)> {
        Self::with_default_handle_and_ip_list(Vec::new())
    }

    /// Spawn a `Responder` on the default tokio handle.
    /// DNS response records will have the reported IPs limited to those passed in here.
    /// This can be particularly useful on machines with lots of networks created by tools such as docker.
    pub fn with_default_handle_and_ip_list(
        allowed_ips: Vec<IpAddr>,
    ) -> io::Result<(Responder, ResponderTask)> {
        let mut hostname = hostname::get()?.into_string().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Hostname not valid unicode")
        })?;

        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        let services = Arc::new(RwLock::new(ServicesInner::new(hostname)));

        let v4 = FSM::<Inet>::new(&services, allowed_ips.clone());
        let v6 = FSM::<Inet6>::new(&services, allowed_ips);

        let (task, commands): (ResponderTask, _) = match (v4, v6) {
            (Ok((v4_task, v4_command)), Ok((v6_task, v6_command))) => {
                let tasks = future::join(v4_task, v6_task).map(|((), ())| ());
                (Box::new(tasks), vec![v4_command, v6_command])
            }

            (Ok((v4_task, v4_command)), Err(err)) => {
                warn!("Failed to register IPv6 receiver: {:?}", err);
                (Box::new(v4_task), vec![v4_command])
            }

            (Err(err), _) => return Err(err),
        };

        let commands = CommandSender(commands);
        let responder = Responder {
            services: services,
            commands: RefCell::new(commands.clone()),
            shutdown: Arc::new(Shutdown(commands)),
        };

        Ok((responder, task))
    }
}

impl Responder {
    /// Register a service to be advertised by the `Responder`. The service is unregistered on
    /// drop.
    ///
    /// # example
    ///
    /// ```no_run
    /// use libmdns::Responder;
    ///
    /// # use std::io;
    /// # fn main() -> io::Result<()> {
    /// let responder = Responder::new()?;
    /// // bind service
    /// let _http_svc = responder.register(
    ///          "_http._tcp".into(),
    ///          "my http server".into(),
    ///          80,
    ///          &["path=/"]
    ///      );
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
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
            port: port,
            txt: txt,
        };

        self.commands
            .borrow_mut()
            .send_unsolicited(svc.clone(), DEFAULT_TTL, true);

        let id = self.services.write().unwrap().register(svc);

        Service {
            id: id,
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
            tx.send(cmd.clone()).expect("responder died");
        }
    }

    fn send_unsolicited(&mut self, svc: ServiceData, ttl: u32, include_ip: bool) {
        self.send(Command::SendUnsolicited {
            svc: svc,
            ttl: ttl,
            include_ip: include_ip,
        });
    }

    fn send_shutdown(&mut self) {
        self.send(Command::Shutdown);
    }
}
