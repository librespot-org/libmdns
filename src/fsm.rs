use crate::dns_parser::{self, Name, QueryClass, QueryType, RRData};
use if_addrs::get_if_addrs;
use log::{debug, error, trace, warn};
use socket2::Domain;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind::WouldBlock;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{net::UdpSocket, sync::mpsc};

use super::{DEFAULT_TTL, MDNS_PORT};
use crate::address_family::AddressFamily;
use crate::services::{ServiceData, Services};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

const SERVICE_TYPE_ENUMERATION_NAME: Cow<'static, str> =
    Cow::Borrowed("_services._dns-sd._udp.local");

#[derive(Clone, Debug)]
pub enum Command {
    SendUnsolicited {
        svc: ServiceData,
        ttl: u32,
        include_ip: bool,
    },
    Shutdown,
}

pub struct FSM<AF: AddressFamily> {
    socket: UdpSocket,
    services: Services,
    commands: mpsc::UnboundedReceiver<Command>,
    outgoing: VecDeque<(Vec<u8>, SocketAddr)>,
    _af: PhantomData<AF>,
    allowed_ip: Vec<IpAddr>,
}

impl<AF: AddressFamily> FSM<AF> {
    // Will panic if called from outside the context of a runtime
    pub fn new(
        services: &Services,
        allowed_ip: Vec<IpAddr>,
    ) -> io::Result<(FSM<AF>, mpsc::UnboundedSender<Command>)> {
        let std_socket = AF::bind()?;
        let socket = UdpSocket::from_std(std_socket)?;

        let (tx, rx) = mpsc::unbounded_channel();

        let fsm = FSM {
            socket: socket,
            services: services.clone(),
            commands: rx,
            outgoing: VecDeque::new(),
            _af: PhantomData,
            allowed_ip: allowed_ip,
        };

        Ok((fsm, tx))
    }

    fn recv_packets(&mut self, cx: &mut Context) -> io::Result<()> {
        let mut recv_buf = [0u8; 65536];
        let mut buf = tokio::io::ReadBuf::new(&mut recv_buf);
        loop {
            let addr = match self.socket.poll_recv_from(cx, &mut buf) {
                Poll::Ready(Ok(addr)) => addr,
                Poll::Ready(Err(err)) => return Err(err),
                Poll::Pending => break,
            };
            self.handle_packet(buf.filled(), addr);
        }

        Ok(())
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
            let addr = SocketAddr::new(AF::MDNS_GROUP.into(), MDNS_PORT);
            self.outgoing.push_back((response, addr));
        }

        if !unicast_builder.is_empty() {
            let response = unicast_builder.build().unwrap_or_else(|x| x);
            self.outgoing.push_back((response, addr));
        }
    }

    /// https://www.rfc-editor.org/rfc/rfc6763#section-9
    fn handle_service_type_enumeration<'a>(
        question: &dns_parser::Question,
        services: impl Iterator<Item = &'a ServiceData>,
        mut builder: AnswerBuilder,
    ) -> AnswerBuilder {
        let service_type_enumeration_name = Name::FromStr(SERVICE_TYPE_ENUMERATION_NAME);
        if question.qname == service_type_enumeration_name {
            for svc in services {
                let svc_type = ServiceData {
                    name: svc.typ.clone(),
                    typ: service_type_enumeration_name.clone(),
                    port: svc.port,
                    txt: vec![],
                };
                builder = svc_type.add_ptr_rr(builder, DEFAULT_TTL);
            }
        }

        builder
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
                builder =
                    Self::handle_service_type_enumeration(question, services.into_iter(), builder);
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
            if !self.allowed_ip.is_empty() && !self.allowed_ip.contains(&iface.ip()) {
                trace!("  -> interface dropped");
                continue;
            }

            match (iface.ip(), AF::DOMAIN) {
                (IpAddr::V4(ip), Domain::IPV4) => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::A(ip))
                }
                (IpAddr::V6(ip), Domain::IPV6) => {
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
            let addr = SocketAddr::new(AF::MDNS_GROUP.into(), MDNS_PORT);
            self.outgoing.push_back((response, addr));
        }
    }
}

impl<AF: Unpin + AddressFamily> Future for FSM<AF> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        let pinned = Pin::get_mut(self);
        while let Poll::Ready(cmd) = Pin::new(&mut pinned.commands).poll_recv(cx) {
            match cmd {
                Some(Command::Shutdown) => return Poll::Ready(()),
                Some(Command::SendUnsolicited {
                    svc,
                    ttl,
                    include_ip,
                }) => {
                    pinned.send_unsolicited(&svc, ttl, include_ip);
                }
                None => {
                    warn!("responder disconnected without shutdown");
                    return Poll::Ready(());
                }
            }
        }

        match pinned.recv_packets(cx) {
            Ok(_) => (),
            Err(e) => error!("ResponderRecvPacket Error: {:?}", e),
        }

        while let Some((ref response, addr)) = pinned.outgoing.pop_front() {
            trace!("sending packet to {:?}", addr);

            match pinned.socket.poll_send_to(cx, response, addr) {
                Poll::Ready(Ok(bytes_sent)) if bytes_sent == response.len() => (),
                Poll::Ready(Ok(_)) => warn!("failed to send entire packet"),
                Poll::Ready(Err(ref ioerr)) if ioerr.kind() == WouldBlock => (),
                Poll::Ready(Err(err)) => warn!("error sending packet {:?}", err),
                Poll::Pending => (),
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address_family::Inet, services::ServicesInner};
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_service_type_enumeration() {
        let question = dns_parser::Question {
            qname: dns_parser::Name::from_str("_services._dns-sd._udp.local").unwrap(),
            qtype: dns_parser::QueryType::PTR,
            qclass: dns_parser::QueryClass::IN,
            qu: false,
        };
        let services = Arc::new(RwLock::new(ServicesInner::new(
            "test-hostname.local".into(),
        )));
        let service_data = ServiceData {
            name: Name::from_str("test-instance").unwrap(),
            typ: Name::from_str("_test-service-name._tcp").unwrap(),
            port: 8008,
            txt: vec![],
        };
        services.write().unwrap().register(service_data);

        let mut answer_builder =
            dns_parser::Builder::new_response(0, false, true).move_to::<dns_parser::Answers>();
        answer_builder.set_max_size(None);

        answer_builder = FSM::<Inet>::handle_service_type_enumeration(
            &question,
            services.read().unwrap().into_iter(),
            answer_builder,
        );

        let packet = answer_builder.build().unwrap();

        let parsed = dns_parser::Packet::parse(&packet).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0].name,
            Name::from_str(SERVICE_TYPE_ENUMERATION_NAME).unwrap()
        );
        assert_eq!(parsed.answers[0].cls, dns_parser::Class::IN);
        assert_eq!(parsed.answers[0].ttl, 60);
        let ptr = match &parsed.answers[0].data {
            RRData::PTR(ptr) => ptr,
            other => panic!("Unexpected answer RR data type: {:?}", other),
        };
        assert_eq!(*ptr, Name::from_str("_test-service-name._tcp").unwrap());
    }
}
