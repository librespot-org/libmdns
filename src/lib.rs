extern crate dns_parser;
#[macro_use] extern crate log;
extern crate net2;
extern crate get_if_addrs;

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::net::IpAddr;
use std::net::UdpSocket;

use net2::UdpBuilder;

use dns_parser::{Name, RRData};

use get_if_addrs::get_if_addrs;

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;
pub trait Database {
    fn query(&self, question: &dns_parser::Question, builder: AnswerBuilder) -> AnswerBuilder;
}

pub struct SimpleDatabase {
    database: HashMap<(dns_parser::Type, Name<'static>), RRData<'static>>
}

impl SimpleDatabase {
    pub fn new() -> SimpleDatabase {
        SimpleDatabase {
            database: HashMap::new()
        }
    }

    pub fn add_record(&mut self,
                      name: Name<'static>,
                      data: RRData<'static>) {
        self.database.insert((data.typ(), name), data);
    }
}

impl Database for SimpleDatabase {
    fn query(&self, question: &dns_parser::Question, builder: AnswerBuilder) -> AnswerBuilder {

        let rrdata = dns_parser::Type::parse(question.qtype as u16).ok()
                        .and_then(|typ| self.database.get(&(typ, question.qname.clone())));

        if let Some(rrdata) = rrdata {
            builder.add_answer(&question.qname, question.qclass, 10, rrdata)
        } else {
            builder
        }
    }
}

pub struct DiscoveryDatabase {
    svc_type: Name<'static>,
    svc_name: Name<'static>,
    hostname: Name<'static>,
    port: u16,
    txt: Vec<u8>,
}

impl DiscoveryDatabase {
    pub fn new(svc_type: String, svc_name: String, hostname: String, port: u16, txt: &[&str]) -> DiscoveryDatabase {
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

        DiscoveryDatabase {
            svc_type: Name::from_str(svc_type).unwrap(),
            svc_name: Name::from_str(svc_name).unwrap(),
            hostname: Name::from_str(hostname).unwrap(),
            port: port,
            txt: txt,
        }
    }
}

impl Database for DiscoveryDatabase {
    fn query(&self, question: &dns_parser::Question, mut builder: AnswerBuilder) -> AnswerBuilder {
        let mut include_ptr = false;
        let mut include_srv = false;
        let mut include_txt = false;
        let mut include_a = false;
        let mut include_aaaa = false;

        if question.qtype == dns_parser::QueryType::PTR && question.qname == Name::from_str("_services._dns-sd._udp.local").unwrap() {
            include_ptr = true;
        }

        if question.qtype == dns_parser::QueryType::PTR && question.qname == self.svc_type {
            include_ptr = true;
        }

        if question.qtype == dns_parser::QueryType::SRV && question.qname == self.svc_name {
            include_srv = true;
        }

        if question.qtype == dns_parser::QueryType::TXT && question.qname == self.svc_name {
            include_txt = true;
        }

        if question.qtype == dns_parser::QueryType::A && question.qname == self.hostname {
            include_a = true;
        }

        if question.qtype == dns_parser::QueryType::AAAA && question.qname == self.hostname {
            include_aaaa = true;
        }

        if include_ptr {
            include_srv = true;
            include_txt = true;
            builder = builder.add_answer(&self.svc_type, question.qclass, 10, &RRData::PTR(self.svc_name.clone()));
        }

        if include_srv {
            include_a = true;
            include_aaaa = true;
            builder = builder.add_answer(&self.svc_name, question.qclass, 10, &RRData::SRV {
                priority: 0,
                weight: 0,
                port: self.port,
                target: self.hostname.clone()
            });
        }

        if include_txt {
            builder = builder.add_answer(&self.svc_name, question.qclass, 10, &RRData::TXT(&self.txt));
        }

        if include_a || include_aaaa {
            for iface in get_if_addrs().unwrap() {
                if iface.is_loopback() {
                    continue;
                }
                match iface.ip() {
                    IpAddr::V4(ip) => {
                        if include_a {
                            builder = builder.add_answer(&self.hostname, question.qclass, 10, &RRData::A(ip))
                        }
                    }
                    IpAddr::V6(ip) => {
                        if include_aaaa {
                            builder = builder.add_answer(&self.hostname, question.qclass, 10, &RRData::AAAA(ip))
                        }
                    }
                }
            }
        }

        builder
    }
}

pub struct Responder<D: Database> {
    database: D,
    socket: UdpSocket,
}

const MDNS_PORT : u16 = 5353;
#[allow(non_snake_case)]
pub fn MDNS_GROUP() -> Ipv4Addr {
    Ipv4Addr::new(224,0,0,251)
}
#[allow(non_snake_case)]
pub fn ANY_ADDR() -> Ipv4Addr {
    Ipv4Addr::new(0,0,0,0)
}

impl <D: Database> Responder<D> {
    pub fn new(database: D) -> io::Result<Responder<D>> {
        let builder = try!(UdpBuilder::new_v4());
        try!(builder.reuse_address(true));
        try!(Self::socket_builder_setup(&builder));

        let socket = try!(builder.bind((ANY_ADDR(), MDNS_PORT)));

        try!(socket.join_multicast_v4(&MDNS_GROUP(), &ANY_ADDR()));

        Ok(Responder {
            database: database,
            socket: socket,
        })
    }

    #[cfg(unix)]
    fn socket_builder_setup(builder: &UdpBuilder) -> io::Result<&UdpBuilder> {
        use net2::unix::UnixUdpBuilderExt;
        builder.reuse_port(true)
    }

    #[cfg(not(unix))]
    fn socket_builder_setup(builder: &UdpBuilder) -> io::Result<&UdpBuilder> {
        Ok(builder)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    pub fn poll(&self) -> io::Result<()> {
        let mut buffer = Vec::new();
        buffer.resize(1500, 0);
        let (size, from) = try!(self.socket.recv_from(&mut buffer));

        if size >= buffer.len() {
            warn!("buffer too small for packet from {:?}", from);
            return Ok(());
        }

        let packet = match dns_parser::Packet::parse(&buffer[..size]) {
            Ok(packet) => packet,
            Err(error) => {
                warn!("couldn't parse packet from {:?}: {}", from, error);
                return Ok(());
            }
        };

        if !packet.header.query {
            return Ok(());
        }

        if packet.header.truncated {
            warn!("dropping truncated packet from {:?}", from);
            return Ok(());
        }

        let mut builder = dns_parser::Builder::new_response(packet.header.id, false);
        builder.set_max_size(None);
        let mut builder = builder.move_to::<dns_parser::Answers>();

        for question in packet.questions {
            println!("{}: {:?} {:?}", question.qname, question.qtype, question.qclass);
            builder = self.database.query(&question, builder);
        }

        let response = builder.build().unwrap_or_else(|x| x);
        try!(self.socket.send_to(&response, (MDNS_GROUP(), MDNS_PORT)));

        Ok(())
    }
}
