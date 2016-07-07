use dns_parser::{self, QueryClass, QueryType, Name, RRData};
use mio;
use mio::{EventSet, PollOpt};
use mio::udp::UdpSocket;
use rotor::{self, GenericScope, Scope, void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io;
use std::io::ErrorKind::Interrupted;
use std::sync::mpsc::{channel, Sender, Receiver, TryRecvError};
use net;
use services::{Services, ServiceData};

const MDNS_PORT : u16 = 5353;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressFamily {
    Inet,
    Inet6,
}

impl AddressFamily {
    fn udp_socket(&self) -> Result<UdpSocket, io::Error> {
        match self {
            &AddressFamily::Inet =>
                UdpSocket::v4(),
            &AddressFamily::Inet6 =>
                UdpSocket::v6(),
        }
    }

    fn mdns_group(&self) -> IpAddr {
        match self {
            &AddressFamily::Inet =>
                IpAddr::V4(Ipv4Addr::new(224,0,0,251)),
            &AddressFamily::Inet6 =>
                IpAddr::V6(Ipv6Addr::new(0xff02,0,0,0,0,0,0,0xfb)),
        }
    }

    fn any_addr(&self) -> IpAddr {
        match self {
            &AddressFamily::Inet =>
                IpAddr::V4(Ipv4Addr::new(0,0,0,0)),
            &AddressFamily::Inet6 =>
                IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,0)),
        }
    }
}

pub const DEFAULT_TTL : u32 = 60;

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

#[derive(Clone)]
pub enum Command {
    SendUnsolicited {
        svc: ServiceData,
        ttl: u32,
        include_ip: bool
    },
    Shutdown,
}


pub struct FSM {
    af: AddressFamily,
    socket: UdpSocket,
    rx: Receiver<Command>,
    services: Services,
}

impl FSM {
    pub fn new(af: AddressFamily, services: &Services) -> io::Result<(FSM, Sender<Command>)> {
        let socket = try!(af.udp_socket());

        net::set_reuse_addr(&socket, true);
        net::set_reuse_port(&socket, true);

        try!(socket.bind(&SocketAddr::new(af.any_addr(), MDNS_PORT)));
        let group = match af.mdns_group() {
            IpAddr::V4(ip) => mio::IpAddr::V4(ip),
            IpAddr::V6(ip) => mio::IpAddr::V6(ip),
        };
        try!(socket.join_multicast(&group));

        let (tx, rx) = channel();
        let fsm = FSM {
            af: af,
            socket: socket,
            rx: rx,
            services: services.clone(),
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
            try!(self.socket.send_to(&response, &SocketAddr::new(self.af.mdns_group(), MDNS_PORT)));
        }

        if !unicast_builder.is_empty() {
            let response = unicast_builder.build().unwrap_or_else(|x| x);
            try!(self.socket.send_to(&response, &addr));
        }

        return Ok(());
    }

    fn handle_question(&self, question: &dns_parser::Question, mut builder: AnswerBuilder) -> AnswerBuilder {
        let services = self.services.read().unwrap();

        match question.qtype {
            QueryType::A |
            QueryType::AAAA |
            QueryType::All if question.qname == *services.get_hostname() => {
                builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
            }
            QueryType::PTR => {
                for svc in services.find_by_type(&question.qname) {
                    builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                    builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
                }
            }
            QueryType::SRV => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
                }
            }
            QueryType::TXT => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                }
            }
            _ => ()
        }

        builder
    }

    fn add_ip_rr(&self, hostname: &Name, mut builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        for iface in net::getifaddrs() {
            if iface.is_loopback() {
                continue;
            }

            match iface.ip() {
                Some(IpAddr::V4(ip)) if self.af == AddressFamily::Inet => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::A(ip))
                }
                Some(IpAddr::V6(ip)) if self.af == AddressFamily::Inet6 => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::AAAA(ip))
                }
                _ => ()
            }
        }

        builder
    }

    fn send_unsolicited(&self, svc: &ServiceData, ttl: u32, include_ip: bool) -> io::Result<()> {
        let mut builder = dns_parser::Builder::new_response(0, false).move_to::<dns_parser::Answers>();
        builder.set_max_size(None);

        let services = self.services.read().unwrap();

        builder = svc.add_ptr_rr(builder, ttl);
        builder = svc.add_srv_rr(services.get_hostname(), builder, ttl);
        builder = svc.add_txt_rr(builder, ttl);
        if include_ip {
            builder = self.add_ip_rr(services.get_hostname(), builder, ttl);
        }

        if !builder.is_empty() {
            let response = builder.build().unwrap_or_else(|x| x);
            try!(self.socket.send_to(&response, &SocketAddr::new(self.af.mdns_group(), MDNS_PORT)));
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

    fn wakeup(self, scope: &mut Scope<Self::Context>) -> rotor::Response<Self, Self::Seed> {
        loop {
            match self.rx.try_recv() {
                Ok(Command::Shutdown) => {
                    scope.shutdown_loop();
                    return rotor::Response::done();
                }
                Ok(Command::SendUnsolicited { svc, ttl, include_ip }) => {
                    match self.send_unsolicited(&svc, ttl, include_ip) {
                        Ok(_) => (),
                        Err(e) => {
                            warn!("Error sending unsolicited: {:?}", e);
                            return rotor::Response::error(Box::new(e));
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
