use futures_util::{future, future::FutureExt};
use log::{trace, warn};
use std::future::Future;
use std::io;
use std::marker::Unpin;
use std::sync::{Arc, RwLock};

use std::thread;
use tokio::{runtime::Handle, sync::broadcast};

mod dns_parser;
use crate::dns_parser::Name;

mod address_family;
mod fsm;
mod services;

use crate::address_family::{Inet, Inet6};
use crate::fsm::{UnsolicitedMessage, FSM};
use crate::services::{ServiceData, Services, ServicesInner};

const DEFAULT_TTL: u32 = 60;
const MDNS_PORT: u16 = 5353;

struct ResponderInner {
    services: Services,
    // These fields are ordered so commands drops first.
    commands: CommandSender,
    // Shutdown::drop will join the thread, so CommandSender must be dropped.
    handle: Shutdown,
}

pub struct Responder {
    inner: Arc<ResponderInner>,
}

pub struct Service {
    id: usize,
    responder: Arc<ResponderInner>,
}

type ResponderTask = Box<dyn Future<Output = ()> + Send + Unpin>;

impl Responder {
    /// Spawn a responder task on an os thread.
    pub fn new() -> io::Result<Responder> {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        let join_handle = thread::Builder::new()
            .name("mdns-responder".to_owned())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    match Self::with_default_handle() {
                        Ok((responder, task)) => {
                            tx.send(Ok(responder)).expect("tx responder channel closed");
                            task.await;
                        }
                        Err(e) => tx.send(Err(e)).expect("tx responder channel closed"),
                    }
                })
            })?;
        let mut responder = rx.recv().expect("rx responder channel closed")?;
        responder.inner.handle.0 = Some(join_handle);
        Ok(responder)
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
        let (responder, task) = Self::with_default_handle()?;
        handle.spawn(task);
        Ok(responder)
    }

    /// Spawn a `Responder` on the default tokio handle.
    pub fn with_default_handle() -> io::Result<(Responder, ResponderTask)> {
        let mut hostname = hostname::get()?.into_string().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Hostname not valid unicode")
        })?;

        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        let (tx, rx1) = broadcast::channel(32);
        let services = Arc::new(RwLock::new(ServicesInner::new(hostname)));

        let v4 = FSM::<Inet>::new(&services, rx1);
        let v6 = FSM::<Inet6>::new(&services, tx.subscribe());

        let task: ResponderTask = match (v4, v6) {
            (Ok(v4_task), Ok(v6_task)) => {
                let tasks = future::join(v4_task, v6_task).map(|((), ())| ());
                Box::new(tasks)
            }

            (Ok(v4_task), Err(err)) => {
                warn!("Failed to register IPv6 receiver: {:?}", err);
                Box::new(v4_task)
            }

            (Err(err), _) => return Err(err),
        };

        let responder = Responder {
            inner: Arc::new(ResponderInner {
                services: services,
                commands: CommandSender(tx),
                handle: Shutdown(None),
            }),
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

        self.inner.commands
            .send_unsolicited(svc.clone(), DEFAULT_TTL, true);

        let id = self.inner.services.write().unwrap().register(svc);

        Service {
            id: id,
            responder: self.inner.clone(),
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let svc = self.responder.services.write().unwrap().unregister(self.id);
        self.responder.commands.send_unsolicited(svc, 0, false);
    }
}

struct Shutdown(Option<thread::JoinHandle<()>>);

impl Drop for Shutdown {
    fn drop(&mut self) {
        trace!("Shutting down...");

        if let Some(handle) = self.0 {
            handle.join().expect("failed to join thread");
        }
    }
}

#[derive(Clone)]
struct CommandSender(broadcast::Sender<UnsolicitedMessage>);
impl CommandSender {
    fn send_unsolicited(&mut self, svc: ServiceData, ttl: u32, include_ip: bool) {
        self.0.send(UnsolicitedMessage {
            svc: svc,
            ttl: ttl,
            include_ip: include_ip,
        }).expect("responder stopped");
    }
}
