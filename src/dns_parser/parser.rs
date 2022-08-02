use std::i32;

use byteorder::{BigEndian, ByteOrder};

use super::{Class, RRData, ResourceRecord, Type};
use super::{Error, Header, Name, Packet, QueryClass, QueryType, Question};

impl<'a> Packet<'a> {
    pub fn parse(data: &[u8]) -> Result<Packet, Error> {
        let header = Header::parse(data)?;
        let mut offset = Header::size();
        let mut questions = Vec::with_capacity(header.questions as usize);
        for _ in 0..header.questions {
            let (name, name_size) = Name::scan(&data[offset..], data)?;
            offset += name_size;
            if offset + 4 > data.len() {
                return Err(Error::UnexpectedEOF);
            }
            let qtype = QueryType::parse(BigEndian::read_u16(&data[offset..offset + 2]))?;
            offset += 2;
            let qclass_qu = BigEndian::read_u16(&data[offset..offset + 2]);
            let qclass = QueryClass::parse(qclass_qu & 0x7fff)?;
            let qu = (qclass_qu & 0x8000) != 0;

            offset += 2;
            questions.push(Question {
                qname: name,
                qtype: qtype,
                qclass: qclass,
                qu: qu,
            });
        }
        let mut answers = Vec::with_capacity(header.answers as usize);
        for _ in 0..header.answers {
            answers.push(parse_record(data, &mut offset)?);
        }
        let mut nameservers = Vec::with_capacity(header.nameservers as usize);
        for _ in 0..header.nameservers {
            nameservers.push(parse_record(data, &mut offset)?);
        }
        Ok(Packet {
            header: header,
            questions: questions,
            answers: answers,
            nameservers: nameservers,
            additional: Vec::new(), // TODO(tailhook)
        })
    }
}

// Generic function to parse answer, nameservers, and additional records.
fn parse_record<'a>(data: &'a [u8], offset: &mut usize) -> Result<ResourceRecord<'a>, Error> {
    let (name, name_size) = Name::scan(&data[*offset..], data)?;
    *offset += name_size;
    if *offset + 10 > data.len() {
        return Err(Error::UnexpectedEOF);
    }
    let typ = Type::parse(BigEndian::read_u16(&data[*offset..*offset + 2]))?;
    *offset += 2;
    let cls = Class::parse(BigEndian::read_u16(&data[*offset..*offset + 2]) & 0x7fff)?;
    *offset += 2;
    let mut ttl = BigEndian::read_u32(&data[*offset..*offset + 4]);
    if ttl > i32::MAX as u32 {
        ttl = 0;
    }
    *offset += 4;
    let rdlen = BigEndian::read_u16(&data[*offset..*offset + 2]) as usize;
    *offset += 2;
    if *offset + rdlen > data.len() {
        return Err(Error::UnexpectedEOF);
    }
    let data = RRData::parse(typ, &data[*offset..*offset + rdlen], data)?;
    *offset += rdlen;
    Ok(ResourceRecord {
        name: name,
        cls: cls,
        ttl: ttl,
        data: data,
    })
}

#[cfg(test)]
mod test {

    use super::super::Opcode::*;
    use super::super::ResponseCode::NoError;
    use super::Class as C;
    use super::QueryClass as QC;
    use super::QueryType as QT;
    use super::RRData;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use {super::Header, super::Packet};

    #[test]
    fn parse_example_query() {
        let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        let packet = Packet::parse(query).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 1573,
                query: true,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                response_code: NoError,
                questions: 1,
                answers: 0,
                nameservers: 0,
                additional: 0,
            }
        );
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "example.com");
        assert_eq!(packet.answers.len(), 0);
    }

    #[test]
    fn parse_name_length_too_long_query() {
        // If the name length provided in the query exceeds the available data we should error
        // rather than panic.
        //
        // Here the entire data section contains only 17 bytes but the first name field length in
        // the query section falsely indicates that the name field contains 17 bytes. If left
        // unchecked this would cause:
        // ```
        // thread 'dns_parser::parser::test::parse_name_length_too_long_query' panicked at 'range
        // end index 18 out of range for slice of length 17'
        // ```
        let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x11example\x03com\x00\x00\x01\x00\x01";
        assert!(Packet::parse(query).is_err());
    }

    #[test]
    fn parse_example_response() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xf8\
                         \x00\x04]\xb8\xd8\"";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 1573,
                query: false,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                response_code: NoError,
                questions: 1,
                answers: 1,
                nameservers: 0,
                additional: 0,
            }
        );
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "example.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "example.com");
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 1272);
        match packet.answers[0].data {
            RRData::A(addr) => {
                assert_eq!(addr, Ipv4Addr::new(93, 184, 216, 34));
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }
    }

    #[test]
    fn parse_ns_response() {
        let response = b"\x4a\xf0\x81\x80\x00\x01\x00\x01\x00\x01\x00\x00\
                         \x03www\x05skype\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\
                         \x00\x1c\x07\x6c\x69\x76\x65\x63\x6d\x73\x0e\x74\
                         \x72\x61\x66\x66\x69\x63\x6d\x61\x6e\x61\x67\x65\
                         \x72\x03\x6e\x65\x74\x00\
                         \xc0\x42\x00\x02\x00\x01\x00\x01\xd5\xd3\x00\x11\
                         \x01\x67\x0c\x67\x74\x6c\x64\x2d\x73\x65\x72\x76\x65\x72\x73\
                         \xc0\x42";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 19184,
                query: false,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                response_code: NoError,
                questions: 1,
                answers: 1,
                nameservers: 1,
                additional: 0,
            }
        );
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "www.skype.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "www.skype.com");
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 3600);
        match packet.answers[0].data {
            RRData::CNAME(ref cname) => {
                assert_eq!(&cname.to_string()[..], "livecms.trafficmanager.net");
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }
        assert_eq!(packet.nameservers.len(), 1);
        assert_eq!(&packet.nameservers[0].name.to_string()[..], "net");
        assert_eq!(packet.nameservers[0].cls, C::IN);
        assert_eq!(packet.nameservers[0].ttl, 120275);
        match packet.nameservers[0].data {
            RRData::NS(ref ns) => {
                assert_eq!(&ns.to_string()[..], "g.gtld-servers.net");
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }
    }

    #[test]
    fn parse_multiple_answers() {
        let response = b"\x9d\xe9\x81\x80\x00\x01\x00\x06\x00\x00\x00\x00\
            \x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\
            \x00\x01\x00\x01\x00\x00\x00\xef\x00\x04@\xe9\
            \xa4d\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\
            \x00\x04@\xe9\xa4\x8b\xc0\x0c\x00\x01\x00\x01\
            \x00\x00\x00\xef\x00\x04@\xe9\xa4q\xc0\x0c\x00\
            \x01\x00\x01\x00\x00\x00\xef\x00\x04@\xe9\xa4f\
            \xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\x00\x04@\
            \xe9\xa4e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\
            \x00\x04@\xe9\xa4\x8a";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 40425,
                query: false,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                response_code: NoError,
                questions: 1,
                answers: 6,
                nameservers: 0,
                additional: 0,
            }
        );
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "google.com");
        assert_eq!(packet.answers.len(), 6);
        let ips = vec![
            Ipv4Addr::new(64, 233, 164, 100),
            Ipv4Addr::new(64, 233, 164, 139),
            Ipv4Addr::new(64, 233, 164, 113),
            Ipv4Addr::new(64, 233, 164, 102),
            Ipv4Addr::new(64, 233, 164, 101),
            Ipv4Addr::new(64, 233, 164, 138),
        ];
        for i in 0..6 {
            assert_eq!(&packet.answers[i].name.to_string()[..], "google.com");
            assert_eq!(packet.answers[i].cls, C::IN);
            assert_eq!(packet.answers[i].ttl, 239);
            match packet.answers[i].data {
                RRData::A(addr) => {
                    assert_eq!(addr, ips[i]);
                }
                ref x => panic!("Wrong rdata {:?}", x),
            }
        }
    }

    #[test]
    fn parse_srv_query() {
        let query = b"[\xd9\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
            \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01";
        let packet = Packet::parse(query).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 23513,
                query: true,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                response_code: NoError,
                questions: 1,
                answers: 0,
                nameservers: 0,
                additional: 0,
            }
        );
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::SRV);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(
            &packet.questions[0].qname.to_string()[..],
            "_xmpp-server._tcp.gmail.com"
        );
        assert_eq!(packet.answers.len(), 0);
    }

    #[test]
    fn parse_srv_response() {
        let response = b"[\xd9\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\
            \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00 \x00\x05\x00\x00\
            \x14\x95\x0bxmpp-server\x01l\x06google\x03com\x00\xc0\x0c\x00!\
            \x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\x14\x95\
            \x04alt3\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt1\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt2\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt4\x0bxmpp-server\x01l\x06google\x03com\x00";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 23513,
                query: false,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                response_code: NoError,
                questions: 1,
                answers: 5,
                nameservers: 0,
                additional: 0,
            }
        );
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::SRV);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(
            &packet.questions[0].qname.to_string()[..],
            "_xmpp-server._tcp.gmail.com"
        );
        assert_eq!(packet.answers.len(), 5);
        let items = vec![
            (5, 0, 5269, "xmpp-server.l.google.com"),
            (20, 0, 5269, "alt3.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt1.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt2.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt4.xmpp-server.l.google.com"),
        ];
        for i in 0..5 {
            assert_eq!(
                &packet.answers[i].name.to_string()[..],
                "_xmpp-server._tcp.gmail.com"
            );
            assert_eq!(packet.answers[i].cls, C::IN);
            assert_eq!(packet.answers[i].ttl, 900);
            match *&packet.answers[i].data {
                RRData::SRV {
                    priority,
                    weight,
                    port,
                    ref target,
                } => {
                    assert_eq!(priority, items[i].0);
                    assert_eq!(weight, items[i].1);
                    assert_eq!(port, items[i].2);
                    assert_eq!(target.to_string(), (items[i].3).to_string());
                }
                ref x => panic!("Wrong rdata {:?}", x),
            }
        }
    }

    #[test]
    fn parse_mx_response() {
        let response = b"\xe3\xe8\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\
            \x05gmail\x03com\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01\
            \x00\x00\x04|\x00\x1b\x00\x05\rgmail-smtp-in\x01l\x06google\xc0\
            \x12\xc0\x0c\x00\x0f\x00\x01\x00\x00\x04|\x00\t\x00\
            \n\x04alt1\xc0)\xc0\x0c\x00\x0f\x00\x01\x00\x00\x04|\
            \x00\t\x00(\x04alt4\xc0)\xc0\x0c\x00\x0f\x00\x01\x00\
            \x00\x04|\x00\t\x00\x14\x04alt2\xc0)\xc0\x0c\x00\x0f\
            \x00\x01\x00\x00\x04|\x00\t\x00\x1e\x04alt3\xc0)";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 58344,
                query: false,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                response_code: NoError,
                questions: 1,
                answers: 5,
                nameservers: 0,
                additional: 0,
            }
        );
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::MX);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "gmail.com");
        assert_eq!(packet.answers.len(), 5);
        let items = vec![
            (5, "gmail-smtp-in.l.google.com"),
            (10, "alt1.gmail-smtp-in.l.google.com"),
            (40, "alt4.gmail-smtp-in.l.google.com"),
            (20, "alt2.gmail-smtp-in.l.google.com"),
            (30, "alt3.gmail-smtp-in.l.google.com"),
        ];
        for i in 0..5 {
            assert_eq!(&packet.answers[i].name.to_string()[..], "gmail.com");
            assert_eq!(packet.answers[i].cls, C::IN);
            assert_eq!(packet.answers[i].ttl, 1148);
            match *&packet.answers[i].data {
                RRData::MX {
                    preference,
                    ref exchange,
                } => {
                    assert_eq!(preference, items[i].0);
                    assert_eq!(exchange.to_string(), (items[i].1).to_string());
                }
                ref x => panic!("Wrong rdata {:?}", x),
            }
        }
    }

    #[test]
    fn parse_aaaa_response() {
        let response = b"\xa9\xd9\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06\
            google\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\
            \x00\x8b\x00\x10*\x00\x14P@\t\x08\x12\x00\x00\x00\x00\x00\x00 \x0e";

        let packet = Packet::parse(response).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 43481,
                query: false,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                response_code: NoError,
                questions: 1,
                answers: 1,
                nameservers: 0,
                additional: 0,
            }
        );

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::AAAA);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "google.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "google.com");
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 139);
        match packet.answers[0].data {
            RRData::AAAA(addr) => {
                assert_eq!(
                    addr,
                    Ipv6Addr::new(0x2A00, 0x1450, 0x4009, 0x812, 0, 0, 0, 0x200e)
                );
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }
    }

    #[test]
    fn parse_cname_response() {
        let response = b"\xfc\x9d\x81\x80\x00\x01\x00\x06\x00\x02\x00\x02\x03\
            cdn\x07sstatic\x03net\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\
            \x00\x00\x00f\x00\x02\xc0\x10\xc0\x10\x00\x01\x00\x01\x00\x00\x00\
            f\x00\x04h\x10g\xcc\xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\
            \x10k\xcc\xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10h\xcc\
            \xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10j\xcc\xc0\x10\
            \x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10i\xcc\xc0\x10\x00\x02\
            \x00\x01\x00\x00\x99L\x00\x0b\x08cf-dns02\xc0\x10\xc0\x10\x00\x02\
            \x00\x01\x00\x00\x99L\x00\x0b\x08cf-dns01\xc0\x10\xc0\xa2\x00\x01\
            \x00\x01\x00\x00\x99L\x00\x04\xad\xf5:5\xc0\x8b\x00\x01\x00\x01\x00\
            \x00\x99L\x00\x04\xad\xf5;\x04";

        let packet = Packet::parse(response).unwrap();
        assert_eq!(
            packet.header,
            Header {
                id: 64669,
                query: false,
                opcode: StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                response_code: NoError,
                questions: 1,
                answers: 6,
                nameservers: 2,
                additional: 2,
            }
        );

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(
            &packet.questions[0].qname.to_string()[..],
            "cdn.sstatic.net"
        );
        assert_eq!(packet.answers.len(), 6);
        assert_eq!(&packet.answers[0].name.to_string()[..], "cdn.sstatic.net");
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 102);
        match packet.answers[0].data {
            RRData::CNAME(ref cname) => {
                assert_eq!(&cname.to_string(), "sstatic.net");
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }

        let ips = vec![
            Ipv4Addr::new(104, 16, 103, 204),
            Ipv4Addr::new(104, 16, 107, 204),
            Ipv4Addr::new(104, 16, 104, 204),
            Ipv4Addr::new(104, 16, 106, 204),
            Ipv4Addr::new(104, 16, 105, 204),
        ];
        for i in 1..6 {
            assert_eq!(&packet.answers[i].name.to_string()[..], "sstatic.net");
            assert_eq!(packet.answers[i].cls, C::IN);
            assert_eq!(packet.answers[i].ttl, 102);
            match packet.answers[i].data {
                RRData::A(addr) => {
                    assert_eq!(addr, ips[i - 1]);
                }
                ref x => panic!("Wrong rdata {:?}", x),
            }
        }
    }
}
