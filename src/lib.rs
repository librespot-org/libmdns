#![deny(clippy::all)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![warn(rust_2018_idioms)]
#![warn(rust_2021_compatibility)]
#![warn(rust_2024_compatibility)]
#![warn(future_incompatible)]

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

/// The default TTL for announced mDNS Services.
pub const DEFAULT_TTL: u32 = 60;
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
    ///
    /// # Panics
    ///
    /// If the tokio runtime cannot be created this will panic.
    #[must_use]
    pub fn new() -> Responder {
        Self::new_with_ip_list(Vec::new()).unwrap()
    }
    /// Spawn a `Responder` task on an new os thread.
    /// DNS response records will have the reported IPs limited to those passed in here.
    /// This can be particularly useful on machines with lots of networks created by tools such as
    /// Docker.
    ///
    /// # Errors
    ///
    /// If the hostname cannot be converted to a valid unicode string, this will return an error.
    ///
    /// # Panics
    ///
    /// If the tokio runtime cannot be created this will panic.
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
                });
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
    ///
    /// # Errors
    ///
    /// If the hostname cannot be converted to a valid unicode string, this will return an error.
    pub fn spawn(handle: &Handle) -> io::Result<Responder> {
        Self::spawn_with_ip_list(handle, Vec::new())
    }

    /// Spawn a `Responder` task  with the provided tokio `Handle`.
    /// DNS response records will have the reported IPs limited to those passed in here.
    /// This can be particularly useful on machines with lots of networks created by tools such as docker.
    ///
    /// # Example
    /// ```no_run
    /// use libmdns::Responder;
    ///
    /// # use std::io;
    /// # fn main() -> io::Result<()> {
    /// let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    /// let handle = rt.handle().clone();
    /// let vec: Vec<std::net::IpAddr> = vec![
    ///     "192.168.1.10".parse::<std::net::Ipv4Addr>().unwrap().into(),
    ///     std::net::Ipv6Addr::new(0, 0, 0, 0xfe80, 0x1ff, 0xfe23, 0x4567, 0x890a).into(),
    /// ];
    /// let responder = Responder::spawn_with_ip_list(&handle, vec)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If the hostname cannot be converted to a valid unicode string, this will return an error.
    pub fn spawn_with_ip_list(handle: &Handle, allowed_ips: Vec<IpAddr>) -> io::Result<Responder> {
        let (responder, task) = Self::with_default_handle_and_ip_list(allowed_ips)?;
        handle.spawn(task);
        Ok(responder)
    }

    /// Spawn a `Responder` task  with the provided tokio `Handle`.
    /// DNS response records will have the reported IPs limited to those passed in here.
    /// This can be particularly useful on machines with lots of networks created by tools such as
    /// Docker.
    /// And SRV field will have specified hostname instead of system hostname.
    /// This can be particularly useful if the platform has the fixed hostname and the application
    /// should make hostname unique for its purpose.
    ///
    /// # Example
    /// ```no_run
    /// use libmdns::Responder;
    ///
    /// # use std::io;
    /// # fn main() -> io::Result<()> {
    /// let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    /// let handle = rt.handle().clone();
    /// let responder = Responder::spawn_with_ip_list_and_hostname(&handle, Vec::new(), "myUniqueName".to_owned())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If the hostname cannot be converted to a valid unicode string, this will return an error.
    pub fn spawn_with_ip_list_and_hostname(
        handle: &Handle,
        allowed_ips: Vec<IpAddr>,
        hostname: String,
    ) -> io::Result<Responder> {
        let (responder, task) =
            Self::with_default_handle_and_ip_list_and_hostname(allowed_ips, hostname)?;
        handle.spawn(task);
        Ok(responder)
    }

    /// Spawn a `Responder` on the default tokio handle.
    ///
    /// # Errors
    ///
    /// If the hostname cannot be converted to a valid unicode string, this will return an error.
    pub fn with_default_handle() -> io::Result<(Responder, ResponderTask)> {
        Self::with_default_handle_and_ip_list(Vec::new())
    }

    /// Spawn a `Responder` on the default tokio handle.
    /// DNS response records will have the reported IPs limited to those passed in here.
    /// This can be particularly useful on machines with lots of networks created by tools such as
    /// Docker.
    ///
    /// # Errors
    ///
    /// If the hostname cannot be converted to a valid unicode string, this will return an error.
    pub fn with_default_handle_and_ip_list(
        allowed_ips: Vec<IpAddr>,
    ) -> io::Result<(Responder, ResponderTask)> {
        let hostname = hostname::get()?.into_string().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Hostname not valid unicode")
        })?;
        Self::default_handle(allowed_ips, hostname)
    }

    /// Spawn a `Responder` on the default tokio handle.
    /// DNS response records will have the reported IPs limited to those passed in here.
    /// This can be particularly useful on machines with lots of networks created by tools such as
    /// Docker.
    /// And SRV field will have specified hostname instead of system hostname.
    /// This can be particularly useful if the platform has the fixed hostname and the application
    /// should make hostname unique for its purpose.
    ///
    /// # Errors
    ///
    /// If the hostname cannot be converted to a valid unicode string, this will return an error.
    pub fn with_default_handle_and_ip_list_and_hostname(
        allowed_ips: Vec<IpAddr>,
        hostname: String,
    ) -> io::Result<(Responder, ResponderTask)> {
        Self::default_handle(allowed_ips, hostname)
    }

    fn default_handle(
        allowed_ips: Vec<IpAddr>,
        mut hostname: String,
    ) -> io::Result<(Responder, ResponderTask)> {
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
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
                warn!("Failed to register IPv6 receiver: {err:?}");
                (Box::new(v4_task), vec![v4_command])
            }

            (Err(err), _) => return Err(err),
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
    /// Register a service to be advertised by the Responder with the [`DEFAULT_TTL`]. The service is unregistered on
    /// drop.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libmdns::Responder;
    ///
    /// # use std::io;
    /// # fn main() -> io::Result<()> {
    /// let responder = Responder::new();
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
    ///
    /// # Panics
    ///
    /// If the TXT records are longer than 255 bytes, this will panic.
    #[must_use]
    pub fn register(&self, svc_type: &str, svc_name: &str, port: u16, txt: &[&str]) -> Service {
        self.register_with_ttl(svc_type, svc_name, port, txt, DEFAULT_TTL)
    }

    /// Register a service to be advertised by the Responder. With a custom TTL in seconds. The service is unregistered on
    /// drop.
    ///
    /// You may prefer to use this over [`Responder::register`] if you know your service will be short-lived and want clients to respond
    /// to it dissapearing more quickly (lower TTL), or if you find your service is very infrequently down and want to reduce
    /// network traffic (higher TTL).
    ///
    /// This becomes more important whilst waiting for <https://github.com/librespot-org/libmdns/issues/27> to be resolved.
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
    /// let _http_svc = responder.register_with_ttl(
    ///          "_http._tcp".into(),
    ///          "my really unreliable and short-lived http server".into(),
    ///          80,
    ///          &["path=/"],
    ///          10 // mDNS clients are requested to re-check every 10 seconds for this HTTP server
    ///      );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// If the TXT records are longer than 255 bytes, this will panic.
    #[must_use]
    pub fn register_with_ttl(
        &self,
        svc_type: &str,
        svc_name: &str,
        port: u16,
        txt: &[&str],
        ttl: u32,
    ) -> Service {
        let txt = if txt.is_empty() {
            vec![0]
        } else {
            txt.iter()
                .flat_map(|entry| {
                    let entry = entry.as_bytes();
                    assert!(
                        (entry.len() <= 255),
                        "{:?} is too long for a TXT record",
                        entry
                    );
                    #[allow(clippy::cast_possible_truncation)]
                    std::iter::once(entry.len() as u8).chain(entry.iter().copied())
                })
                .collect()
        };

        let svc = ServiceData {
            typ: Name::from_str(format!("{svc_type}.local")),
            name: Name::from_str(format!("{svc_name}.{svc_type}.local")),
            port,
            txt,
        };

        self.commands
            .borrow_mut()
            .send_unsolicited(svc.clone(), ttl, true);

        let id = self.services.write().unwrap().register(svc);

        Service {
            id,
            commands: self.commands.borrow().clone(),
            services: self.services.clone(),
            _shutdown: self.shutdown.clone(),
        }
    }
}

impl Default for Responder {
    fn default() -> Self {
        Responder::new()
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
    #[allow(clippy::needless_pass_by_value)]
    fn send(&mut self, cmd: Command) {
        for tx in &mut self.0 {
            tx.send(cmd.clone()).expect("responder died");
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
