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
use crate::services::{ServiceData, Services, ServicesInner};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;
pub type AdditionalBuilder = dns_parser::Builder<dns_parser::Additional>;

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

#[allow(clippy::upper_case_acronyms)]
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
            socket,
            services: services.clone(),
            commands: rx,
            outgoing: VecDeque::new(),
            _af: PhantomData,
            allowed_ip,
        };

        Ok((fsm, tx))
    }

    fn recv_packets(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        // Buffer size discussed in: https://github.com/librespot-org/libmdns/pull/40
        let mut recv_buf = vec![0u8; 65536].into_boxed_slice();
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
        trace!("received packet from {addr:?}");

        let packet = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => packet,
            Err(error) => {
                warn!("couldn't parse packet from {addr:?}: {error}");
                return;
            }
        };

        if !packet.header.query {
            trace!("received packet from {addr:?} with no query");
            return;
        }

        if packet.header.truncated {
            warn!("dropping truncated packet from {addr:?}");
            return;
        }

        for question in packet.questions {
            debug!(
                "received question: {:?} {}",
                question.qclass, question.qname
            );

            if question.qclass == QueryClass::IN || question.qclass == QueryClass::Any {
                let mut builder = dns_parser::Builder::new_response(packet.header.id, false, true)
                    .move_to::<dns_parser::Answers>();
                builder.set_max_size(None);
                let builder = self.handle_question(&question, builder);
                if builder.is_empty() {
                    continue;
                }
                let response = builder.build().unwrap_or_else(|x| x);
                if question.qu {
                    self.outgoing.push_back((response, addr));
                } else {
                    let addr = SocketAddr::new(AF::MDNS_GROUP.into(), MDNS_PORT);
                    self.outgoing.push_back((response, addr));
                }
            }
        }
    }

    /// <https://www.rfc-editor.org/rfc/rfc6763#section-9>
    fn handle_service_type_enumeration<'a>(
        question: &dns_parser::Question<'_>,
        services: &ServicesInner,
        mut builder: AnswerBuilder,
    ) -> AnswerBuilder {
        let service_type_enumeration_name = Name::FromStr(SERVICE_TYPE_ENUMERATION_NAME);
        if question.qname == service_type_enumeration_name {
            for typ in services.all_types() {
                builder = builder.add_answer(
                    &service_type_enumeration_name,
                    QueryClass::IN,
                    DEFAULT_TTL,
                    &RRData::PTR(typ.clone()),
                );
            }
        }

        builder
    }

    fn handle_question(
        &self,
        question: &dns_parser::Question<'_>,
        mut builder: AnswerBuilder,
    ) -> AdditionalBuilder {
        let services = self.services.read().unwrap();
        let hostname = services.get_hostname();

        match question.qtype {
            QueryType::A | QueryType::AAAA if question.qname == *hostname => builder
                .add_answers(hostname, QueryClass::IN, DEFAULT_TTL, self.ip_rr())
                .move_to(),
            QueryType::All => {
                let mut include_ip_additionals = false;
                // A / AAAA
                if question.qname == *hostname {
                    builder =
                        builder.add_answers(hostname, QueryClass::IN, DEFAULT_TTL, self.ip_rr());
                }
                // PTR
                builder = Self::handle_service_type_enumeration(question, &services, builder);
                for svc in services.find_by_type(&question.qname) {
                    builder =
                        builder.add_answer(&svc.typ, QueryClass::IN, DEFAULT_TTL, &svc.ptr_rr());
                    include_ip_additionals = true;
                }
                // SRV
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder = builder
                        .add_answer(
                            &svc.name,
                            QueryClass::IN,
                            DEFAULT_TTL,
                            &svc.srv_rr(hostname),
                        )
                        .add_answer(&svc.name, QueryClass::IN, DEFAULT_TTL, &svc.txt_rr());
                    include_ip_additionals = true;
                }
                let mut builder = builder.move_to::<dns_parser::Additional>();
                // PTR (additional)
                for svc in services.find_by_type(&question.qname) {
                    builder = builder
                        .add_additional(
                            &svc.name,
                            QueryClass::IN,
                            DEFAULT_TTL,
                            &svc.srv_rr(hostname),
                        )
                        .add_additional(&svc.name, QueryClass::IN, DEFAULT_TTL, &svc.txt_rr());
                    include_ip_additionals = true;
                }

                if include_ip_additionals {
                    builder = builder.add_additionals(
                        hostname,
                        QueryClass::IN,
                        DEFAULT_TTL,
                        self.ip_rr(),
                    );
                }
                builder
            }
            QueryType::PTR => {
                let mut include_ip_additionals = false;
                let mut builder =
                    Self::handle_service_type_enumeration(question, &services, builder);
                for svc in services.find_by_type(&question.qname) {
                    builder =
                        builder.add_answer(&svc.typ, QueryClass::IN, DEFAULT_TTL, &svc.ptr_rr())
                }
                let mut builder = builder.move_to::<dns_parser::Additional>();
                for svc in services.find_by_type(&question.qname) {
                    builder = builder
                        .add_additional(
                            &svc.name,
                            QueryClass::IN,
                            DEFAULT_TTL,
                            &svc.srv_rr(hostname),
                        )
                        .add_additional(&svc.name, QueryClass::IN, DEFAULT_TTL, &svc.txt_rr());
                    include_ip_additionals = true;
                }
                if include_ip_additionals {
                    builder = builder.add_additionals(
                        hostname,
                        QueryClass::IN,
                        DEFAULT_TTL,
                        self.ip_rr(),
                    );
                }
                builder
            }
            QueryType::SRV => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder
                        .add_answer(
                            &svc.name,
                            QueryClass::IN,
                            DEFAULT_TTL,
                            &svc.srv_rr(hostname),
                        )
                        .add_additionals(hostname, QueryClass::IN, DEFAULT_TTL, self.ip_rr())
                        .move_to()
                } else {
                    builder.move_to()
                }
            }
            QueryType::TXT => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder
                        .add_answer(&svc.name, QueryClass::IN, DEFAULT_TTL, &svc.txt_rr())
                        .move_to()
                } else {
                    builder.move_to()
                }
            }
            _ => builder.move_to(),
        }
    }

    fn ip_rr(&self) -> impl Iterator<Item = RRData<'static>> + '_ {
        let interfaces = match get_if_addrs() {
            Ok(interfaces) => interfaces,
            Err(err) => {
                error!("could not get list of interfaces: {}", err);
                vec![]
            }
        };
        interfaces.into_iter().filter_map(move |iface| {
            if iface.is_loopback() {
                return None;
            }

            trace!("found interface {iface:?}");
            if !self.allowed_ip.is_empty() && !self.allowed_ip.contains(&iface.ip()) {
                trace!("  -> interface dropped");
                return None;
            }

            match (iface.ip(), AF::DOMAIN) {
                (IpAddr::V4(ip), Domain::IPV4) => Some(RRData::A(ip)),
                (IpAddr::V6(ip), Domain::IPV6) => Some(RRData::AAAA(ip)),
                _ => None,
            }
        })
    }

    fn send_unsolicited(&mut self, svc: &ServiceData, ttl: u32, include_ip: bool) {
        let mut builder =
            dns_parser::Builder::new_response(0, false, true).move_to::<dns_parser::Answers>();
        builder.set_max_size(None);

        let services = self.services.read().unwrap();

        builder = builder.add_answer(&svc.typ, QueryClass::IN, ttl, &svc.ptr_rr());
        builder = builder.add_answer(
            &svc.name,
            QueryClass::IN,
            ttl,
            &svc.srv_rr(services.get_hostname()),
        );
        builder = builder.add_answer(&svc.name, QueryClass::IN, ttl, &svc.txt_rr());
        if include_ip {
            builder =
                builder.add_answers(services.get_hostname(), QueryClass::IN, ttl, self.ip_rr());
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
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
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
            Ok(()) => (),
            Err(e) => error!("ResponderRecvPacket Error: {e:?}"),
        }

        while let Some((ref response, addr)) = pinned.outgoing.pop_front() {
            trace!("sending packet to {addr:?}");

            match pinned.socket.poll_send_to(cx, response, addr) {
                Poll::Ready(Ok(bytes_sent)) if bytes_sent == response.len() => (),
                Poll::Ready(Ok(_)) => warn!("failed to send entire packet"),
                Poll::Ready(Err(ref ioerr)) if ioerr.kind() == WouldBlock => (),
                Poll::Ready(Err(err)) => warn!("error sending packet {err:?}"),
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
            qname: dns_parser::Name::from_str("_services._dns-sd._udp.local"),
            qtype: dns_parser::QueryType::PTR,
            qclass: dns_parser::QueryClass::IN,
            qu: false,
        };
        let services = Arc::new(RwLock::new(ServicesInner::new(
            "test-hostname.local".into(),
        )));
        let service_data = ServiceData {
            name: Name::from_str("test-instance"),
            typ: Name::from_str("_test-service-name._tcp"),
            port: 8008,
            txt: vec![],
        };
        services.write().unwrap().register(service_data);

        let mut answer_builder =
            dns_parser::Builder::new_response(0, false, true).move_to::<dns_parser::Answers>();
        answer_builder.set_max_size(None);

        answer_builder = FSM::<Inet>::handle_service_type_enumeration(
            &question,
            &services.read().unwrap(),
            answer_builder,
        );

        let packet = answer_builder.build().unwrap();

        let parsed = dns_parser::Packet::parse(&packet).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0].name,
            Name::from_str(SERVICE_TYPE_ENUMERATION_NAME),
        );
        assert_eq!(parsed.answers[0].cls, dns_parser::Class::IN);
        assert_eq!(parsed.answers[0].ttl, 60);
        let ptr = match &parsed.answers[0].data {
            RRData::PTR(ptr) => ptr,
            other => panic!("Unexpected answer RR data type: {:?}", other),
        };
        assert_eq!(*ptr, Name::from_str("_test-service-name._tcp"));
    }
}
