use dns_parser::{self, QueryClass, QueryType, Name, RRData};
use eventual;
use mio;
use mio::{EventSet, PollOpt};
use mio::udp::UdpSocket;
use rand::{Rng, thread_rng};
use rotor::{self, GenericScope, Scope, void, Void};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::io;
use std::io::ErrorKind::Interrupted;
use std::sync::mpsc::{channel, Sender, Receiver, TryRecvError};
use std::collections::HashMap;
use multimap::MultiMap;
use net;

const MDNS_PORT : u16 = 5353;
#[allow(non_snake_case)]
pub fn MDNS_GROUP() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(224,0,0,251))
}
#[allow(non_snake_case)]
pub fn ANY_ADDR() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0,0,0,0))
}

const DEFAULT_TTL : u32 = 60;

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

pub enum Command {
    Shutdown,
    Register(ServiceData, eventual::Complete<usize, Void>),
    Unregister(usize),
}

pub struct ServiceData {
    pub name: Name<'static>,
    pub typ: Name<'static>,
    pub port: u16,
    pub txt: Vec<u8>,
}

pub struct FSM {
    socket: UdpSocket,
    rx: Receiver<Command>,

    hostname: Name<'static>,
    services: HashMap<usize, ServiceData>,
    by_type: MultiMap<Name<'static>, usize>,
    by_name: HashMap<Name<'static>, usize>
}

impl FSM {
    pub fn new() -> io::Result<(FSM, Sender<Command>)> {
        let socket = try!(UdpSocket::v4());

        net::set_reuse_addr(&socket, true);
        net::set_reuse_port(&socket, true);

        try!(socket.bind(&SocketAddr::new(ANY_ADDR(), MDNS_PORT)));
        let group = match MDNS_GROUP() {
            IpAddr::V4(ip) => mio::IpAddr::V4(ip),
            IpAddr::V6(ip) => mio::IpAddr::V6(ip),
        };
        try!(socket.join_multicast(&group));

        let mut hostname = try!(net::gethostname());
        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        let (tx, rx) = channel();
        let fsm = FSM {
            socket: socket,
            rx: rx,
            hostname: Name::from_str(hostname).unwrap(),
            services: HashMap::new(),
            by_type: MultiMap::new(),
            by_name: HashMap::new(),
        };

        Ok((fsm, tx))
    }

    pub fn register<S: GenericScope>(&self, scope: &mut S) -> io::Result<()> {
        scope.register(&self.socket, EventSet::readable(), PollOpt::level())
    }

    fn recv_packets(&self) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let (bytes, addr) = match self.socket.recv_from(&mut buf) {
                Ok(Some((bytes, addr))) => (bytes, addr),
                Ok(None) => break,
                Err(ref ioerr) if ioerr.kind() == Interrupted => continue,
                Err(err) => return Err(err),
            };

            if bytes >= buf.len() {
                warn!("buffer too small for packet from {:?}", addr);
                continue;
            }

            try!(self.handle_packet(&buf[..bytes], addr));
        }
        return Ok(())
    }

    fn handle_packet(&self, buffer: &[u8], addr: SocketAddr) -> io::Result<()> {
        let packet = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => packet,
            Err(error) => {
                warn!("couldn't parse packet from {:?}: {}", addr, error);
                return Ok(());
            }
        };

        if !packet.header.query {
            return Ok(());
        }

        if packet.header.truncated {
            warn!("dropping truncated packet from {:?}", addr);
            return Ok(());
        }

        let mut unicast_builder = dns_parser::Builder::new_response(packet.header.id, false).move_to::<dns_parser::Answers>();
        let mut multicast_builder = dns_parser::Builder::new_response(packet.header.id, false).move_to::<dns_parser::Answers>();
        unicast_builder.set_max_size(None);
        multicast_builder.set_max_size(None);

        for question in packet.questions {
            if question.qclass == QueryClass::IN || question.qclass == QueryClass::Any {
                if question.qu {
                    unicast_builder = self.handle_question(&question, unicast_builder);
                } else {
                    multicast_builder = self.handle_question(&question, multicast_builder);
                }
            }
        }

        if !multicast_builder.is_empty() {
            let response = multicast_builder.build().unwrap_or_else(|x| x);
            try!(self.socket.send_to(&response, &SocketAddr::new(MDNS_GROUP(), MDNS_PORT)));
        }

        if !unicast_builder.is_empty() {
            let response = unicast_builder.build().unwrap_or_else(|x| x);
            try!(self.socket.send_to(&response, &addr));
        }

        return Ok(());
    }

    fn handle_question(&self, question: &dns_parser::Question, mut builder: AnswerBuilder) -> AnswerBuilder {
        match question.qtype {
            QueryType::A |
            QueryType::AAAA |
            QueryType::All if question.qname == self.hostname => {
                builder = self.add_ip_rr(builder, DEFAULT_TTL);
            }
            QueryType::PTR => {
                for id in self.by_type.get_vec(&question.qname).unwrap_or(&vec![]) {
                    let svc = self.services.get(id).expect("missing service");
                    builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                    builder = svc.add_srv_rr(&self.hostname, builder, DEFAULT_TTL);
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(builder, DEFAULT_TTL);
                }
            }
            QueryType::SRV => {
                if let Some(id) = self.by_name.get(&question.qname) {
                    let svc = self.services.get(id).expect("missing service");
                    builder = svc.add_srv_rr(&self.hostname, builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(builder, DEFAULT_TTL);
                }
            }
            QueryType::TXT => {
                if let Some(id) = self.by_name.get(&question.qname) {
                    let svc = self.services.get(id).expect("missing service");
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                }
            }
            _ => ()
        }

        builder
    }

    fn add_ip_rr(&self, mut builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        for iface in net::getifaddrs() {
            if iface.is_loopback() {
                continue;
            }

            match iface.ip() {
                Some(IpAddr::V4(ip)) => {
                    builder = builder.add_answer(&self.hostname, QueryClass::IN, ttl, &RRData::A(ip))
                }
                Some(IpAddr::V6(ip)) => {
                    builder = builder.add_answer(&self.hostname, QueryClass::IN, ttl, &RRData::AAAA(ip))
                }
                None => ()
            }
        }

        builder
    }

    fn send_unsolicited(&self, svc: &ServiceData, ttl: u32, include_ip: bool) -> io::Result<()> {
        let mut builder = dns_parser::Builder::new_response(0, false).move_to::<dns_parser::Answers>();
        builder.set_max_size(None);

        builder = svc.add_ptr_rr(builder, ttl);
        builder = svc.add_srv_rr(&self.hostname, builder, ttl);
        builder = svc.add_txt_rr(builder, ttl);
        if include_ip {
            builder = self.add_ip_rr(builder, ttl);
        }

        if !builder.is_empty() {
            let response = builder.build().unwrap_or_else(|x| x);
            try!(self.socket.send_to(&response, &SocketAddr::new(MDNS_GROUP(), MDNS_PORT)));
        }

        Ok(())
    }
}

impl rotor::Machine for FSM {
    type Context = ();
    type Seed = void::Void;

    fn create(seed: Self::Seed, _scope: &mut Scope<Self::Context>) -> rotor::Response<Self, rotor::Void> {
        void::unreachable(seed)
    }

    fn ready(self, _events: EventSet, _scope: &mut Scope<Self::Context>) -> rotor::Response<Self, Self::Seed> {
        self.recv_packets().unwrap();
        rotor::Response::ok(self)
    }

    fn spawned(self, _scope: &mut Scope<Self::Context>) -> rotor::Response<Self, Self::Seed> {
        unimplemented!()
    }

    fn timeout(self, _scope: &mut Scope<Self::Context>) -> rotor::Response<Self, Self::Seed> {
        unimplemented!()
    }

    fn wakeup(mut self, scope: &mut Scope<Self::Context>) -> rotor::Response<Self, Self::Seed> {
        loop {
            match self.rx.try_recv() {
                Ok(Command::Shutdown) => {
                    scope.shutdown_loop();
                    return rotor::Response::done();
                }
                Ok(Command::Register(svc, complete)) => {
                    let mut id = thread_rng().gen::<usize>();
                    while self.services.contains_key(&id) {
                        id = thread_rng().gen::<usize>();
                    }

                    trace!("registering {} {}", svc.name, id);

                    self.send_unsolicited(&svc, DEFAULT_TTL, true).unwrap();

                    self.by_type.insert(svc.typ.clone(), id);
                    self.by_name.insert(svc.name.clone(), id);
                    self.services.insert(id, svc);

                    complete.complete(id);
                }
                Ok(Command::Unregister(id)) => {
                    use std::collections::hash_map::Entry;

                    let svc = self.services.remove(&id).expect("unknown service");

                    trace!("unregistering {} {}", svc.name, id);
                    self.send_unsolicited(&svc, 0, false).unwrap();

                    if let Some(entries) = self.by_type.get_vec_mut(&svc.typ) {
                        entries.retain(|&e| e == id);
                    }

                    match self.by_name.entry(svc.name) {
                        Entry::Occupied(entry) => {
                            assert_eq!(*entry.get(), id);
                            entry.remove();
                        }
                        _ => {
                            panic!("unknown/wrong service for id {}", id);
                        }
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    warn!("responder disconnected without shutdown");
                    scope.shutdown_loop();
                    return rotor::Response::done();
                }
                Err(TryRecvError::Empty) => {
                    break;
                }
            }
        }

        rotor::Response::ok(self)
    }
}

impl ServiceData {
    fn add_ptr_rr(&self, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(&self.typ, QueryClass::IN, ttl, &RRData::PTR(self.name.clone()))
    }

    fn add_srv_rr(&self, hostname: &Name, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(&self.name, QueryClass::IN, ttl, &RRData::SRV {
            priority: 0,
            weight: 0,
            port: self.port,
            target: hostname.clone(),
        })
    }

    fn add_txt_rr(&self, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(&self.name, QueryClass::IN, ttl, &RRData::TXT(&self.txt))
    }
}
