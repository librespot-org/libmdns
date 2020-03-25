use crate::dns_parser::{self, Name, QueryClass, QueryType, RRData};
use futures::channel::mpsc;
use futures::future::*;
use get_if_addrs::get_if_addrs;
use std::pin::Pin;
use std::task::*;

use std::collections::VecDeque;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

use super::{DEFAULT_TTL, MDNS_PORT};

use crate::address_family::AddressFamily;
use crate::services::{ServiceData, Services};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

#[derive(Clone, Debug)]
pub enum Command {
    SendUnsolicited {
        svc: ServiceData,
        ttl: u32,
        include_ip: bool,
    },
    Shutdown,
}

#[pin_project::pin_project]
pub struct FSM<AF: AddressFamily> {
    socket: UdpSocket,
    services: Services,
    commands: mpsc::UnboundedReceiver<Command>,
    outgoing: VecDeque<(Vec<u8>, SocketAddr)>,
    _af: PhantomData<AF>,
}


impl<AF: AddressFamily> FSM<AF> {
    pub fn new(services: &Services) -> io::Result<(FSM<AF>, mpsc::UnboundedSender<Command>)> {
        let std_socket = AF::bind()?;
        let socket = UdpSocket::from_std(std_socket)?;
        let (tx, rx) = mpsc::unbounded();

        let fsm = FSM {
            socket,
            services: services.clone(),
            commands: rx,
            outgoing: VecDeque::new(),
            _af: PhantomData,
        };

        Ok((fsm, tx))
    }
}


#[pin_project::project]
impl<AF: AddressFamily> FSM<AF> {

    fn recv_packets(
        &mut self,
        ctx: &mut std::task::Context,
    ) -> io::Result<()> {
        let mut buf = [0u8; 4096];

        match self.socket.poll_recv_from(ctx,&mut buf) {
            Poll::Ready(Ok((bytes, addr))) => {
                if bytes >= buf.len() {
                    warn!("buffer too small for packet from {:?}", addr);
                    Ok(())
                } else {
                    self.handle_packet(&buf[..bytes], addr);
                    Ok(())
                }
            }
            Poll::Ready(Err(err)) => Err(err),
            _ => Ok(())
        }
    }

    fn handle_packet(&mut self, buffer: &[u8], addr: SocketAddr) {
        trace!("received packet from {:?}", addr);

        let packet = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => packet,
            Err(error) => {
                warn!("couldn't parse packet from {:?}: {}", addr, error);
                return;
            }
        };

        if !packet.header.query {
            trace!("received packet from {:?} with no query", addr);
            return;
        }

        if packet.header.truncated {
            warn!("dropping truncated packet from {:?}", addr);
            return;
        }

        let mut unicast_builder = dns_parser::Builder::new_response(packet.header.id, false, true)
            .move_to::<dns_parser::Answers>();
        let mut multicast_builder =
            dns_parser::Builder::new_response(packet.header.id, false, true)
                .move_to::<dns_parser::Answers>();
        unicast_builder.set_max_size(None);
        multicast_builder.set_max_size(None);

        for question in packet.questions {
            debug!(
                "received question: {:?} {}",
                question.qclass, question.qname
            );

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
            let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
            self.outgoing.push_back((response, addr));
        }

        if !unicast_builder.is_empty() {
            let response = unicast_builder.build().unwrap_or_else(|x| x);
            self.outgoing.push_back((response, addr));
        }
    }

    fn handle_question(
        &self,
        question: &dns_parser::Question,
        mut builder: AnswerBuilder,
    ) -> AnswerBuilder {
        let services = self.services.read().unwrap();

        match question.qtype {
            QueryType::A | QueryType::AAAA | QueryType::All
                if question.qname == *services.get_hostname() =>
            {
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
            _ => (),
        }

        builder
    }

    fn add_ip_rr(&self, hostname: &Name, mut builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        let interfaces = match get_if_addrs() {
            Ok(interfaces) => interfaces,
            Err(err) => {
                error!("could not get list of interfaces: {}", err);
                return builder;
            }
        };

        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }

            trace!("found interface {:?}", iface);
            match iface.ip() {
                IpAddr::V4(ip) if !AF::v6() => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::A(ip))
                }
                IpAddr::V6(ip) if AF::v6() => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::AAAA(ip))
                }
                _ => (),
            }
        }

        builder
    }

    fn send_unsolicited(&mut self, svc: &ServiceData, ttl: u32, include_ip: bool) {
        let mut builder =
            dns_parser::Builder::new_response(0, false, true).move_to::<dns_parser::Answers>();
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
            let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
            self.outgoing.push_back((response, addr));
        }
    }


    fn poll_project(&mut self, ctx: &mut std::task::Context) -> Poll<Result<(),io::Error>> {

        while let Ok(cmd) = self.commands.try_next() {
            match cmd {
                Some(Command::Shutdown) => return Poll::Ready(Ok(())),
                Some(Command::SendUnsolicited {
                    svc,
                    ttl,
                    include_ip,
                }) => {
                    self.send_unsolicited(&svc, ttl, include_ip);
                }
                None => {
                    warn!("responder disconnected without shutdown");
                    return Poll::Ready(Ok(()));
                }
            }
        }

        self.recv_packets(ctx)?;

        loop {
            if let Some(&(ref response, ref addr)) = self.outgoing.front() {
                trace!("sending packet to {:?}", addr);

                match self.socket.poll_send_to(ctx, response, addr) {
                    Poll::Ready(Ok(_)) => {
                        self.outgoing.pop_front();
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("error sending packet {:?}", err);
                        self.outgoing.pop_front();
                    }
                    Poll::Pending => break,
                }
            }
        }

        Poll::Pending
    }
}

impl<AF: AddressFamily> Future for FSM<AF> {
    type Output = Result<(), io::Error>;

    fn poll(self: Pin<&mut Self>, ctx: &mut std::task::Context) -> Poll<Self::Output> {
        self.project().poll_project(ctx)
    }
}
