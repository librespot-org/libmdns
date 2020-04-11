use byteorder::{BigEndian, ByteOrder};

use super::{Error, Opcode, ResponseCode};

mod flag {
    pub const QUERY: u16 = 0b1000_0000_0000_0000;
    pub const OPCODE_MASK: u16 = 0b0111_1000_0000_0000;
    pub const AUTHORITATIVE: u16 = 0b0000_0100_0000_0000;
    pub const TRUNCATED: u16 = 0b0000_0010_0000_0000;
    pub const RECURSION_DESIRED: u16 = 0b0000_0001_0000_0000;
    pub const RECURSION_AVAILABLE: u16 = 0b0000_0000_1000_0000;
    pub const RESERVED_MASK: u16 = 0b0000_0000_0111_0000;
    pub const RESPONSE_CODE_MASK: u16 = 0b0000_0000_0000_1111;
}

/// Represents parsed header of the packet
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Header {
    pub id: u16,
    pub query: bool,
    pub opcode: Opcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
    pub questions: u16,
    pub answers: u16,
    pub nameservers: u16,
    pub additional: u16,
}

impl Header {
    pub fn parse(data: &[u8]) -> Result<Header, Error> {
        if data.len() < 12 {
            return Err(Error::HeaderTooShort);
        }
        let flags = BigEndian::read_u16(&data[2..4]);
        if flags & flag::RESERVED_MASK != 0 {
            return Err(Error::ReservedBitsAreNonZero);
        }
        let header = Header {
            id: BigEndian::read_u16(&data[..2]),
            query: flags & flag::QUERY == 0,
            opcode: (flags & flag::OPCODE_MASK >> flag::OPCODE_MASK.trailing_zeros()).into(),
            authoritative: flags & flag::AUTHORITATIVE != 0,
            truncated: flags & flag::TRUNCATED != 0,
            recursion_desired: flags & flag::RECURSION_DESIRED != 0,
            recursion_available: flags & flag::RECURSION_AVAILABLE != 0,
            response_code: From::from((flags & flag::RESPONSE_CODE_MASK) as u8),
            questions: BigEndian::read_u16(&data[4..6]),
            answers: BigEndian::read_u16(&data[6..8]),
            nameservers: BigEndian::read_u16(&data[8..10]),
            additional: BigEndian::read_u16(&data[10..12]),
        };
        Ok(header)
    }
    /// Write a header to a buffer slice
    ///
    /// # Panics
    ///
    /// When buffer size is not exactly 12 bytes
    pub fn write(&self, data: &mut [u8]) {
        if data.len() != 12 {
            panic!("Header size is exactly 12 bytes");
        }
        let mut flags = 0u16;
        flags |= Into::<u16>::into(self.opcode) << flag::OPCODE_MASK.trailing_zeros();
        flags |= Into::<u8>::into(self.response_code) as u16;
        if !self.query {
            flags |= flag::QUERY;
        }
        if self.authoritative {
            flags |= flag::AUTHORITATIVE;
        }
        if self.recursion_desired {
            flags |= flag::RECURSION_DESIRED;
        }
        if self.recursion_available {
            flags |= flag::RECURSION_AVAILABLE;
        }
        if self.truncated {
            flags |= flag::TRUNCATED;
        }
        BigEndian::write_u16(&mut data[..2], self.id);
        BigEndian::write_u16(&mut data[2..4], flags);
        BigEndian::write_u16(&mut data[4..6], self.questions);
        BigEndian::write_u16(&mut data[6..8], self.answers);
        BigEndian::write_u16(&mut data[8..10], self.nameservers);
        BigEndian::write_u16(&mut data[10..12], self.additional);
    }
    pub fn set_truncated(data: &mut [u8]) {
        let oldflags = BigEndian::read_u16(&data[2..4]);
        BigEndian::write_u16(&mut data[2..4], oldflags & flag::TRUNCATED);
    }

    pub fn question_count(data: &[u8]) -> u16 {
        BigEndian::read_u16(&data[4..6])
    }

    pub fn answer_count(data: &[u8]) -> u16 {
        BigEndian::read_u16(&data[6..8])
    }

    pub fn nameserver_count(data: &[u8]) -> u16 {
        BigEndian::read_u16(&data[8..10])
    }

    pub fn additional_count(data: &[u8]) -> u16 {
        BigEndian::read_u16(&data[10..12])
    }

    pub fn inc_questions(data: &mut [u8]) -> Option<u16> {
        let oldq = BigEndian::read_u16(&data[4..6]);
        if oldq < 65535 {
            BigEndian::write_u16(&mut data[4..6], oldq + 1);
            Some(oldq + 1)
        } else {
            None
        }
    }

    pub fn inc_answers(data: &mut [u8]) -> Option<u16> {
        let oldq = BigEndian::read_u16(&data[6..8]);
        if oldq < 65535 {
            BigEndian::write_u16(&mut data[6..8], oldq + 1);
            Some(oldq + 1)
        } else {
            None
        }
    }

    pub fn inc_nameservers(data: &mut [u8]) -> Option<u16> {
        let oldq = BigEndian::read_u16(&data[8..10]);
        if oldq < 65535 {
            BigEndian::write_u16(&mut data[8..10], oldq + 1);
            Some(oldq + 1)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn inc_additional(data: &mut [u8]) -> Option<u16> {
        let oldq = BigEndian::read_u16(&data[10..12]);
        if oldq < 65535 {
            BigEndian::write_u16(&mut data[10..12], oldq + 1);
            Some(oldq + 1)
        } else {
            None
        }
    }
    pub fn size() -> usize {
        12
    }
}

#[cfg(test)]
mod test {

    use super::Header;
    use super::Opcode::*;
    use super::ResponseCode::NoError;

    #[test]
    fn parse_example_query() {
        let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        let header = Header::parse(query).unwrap();
        assert_eq!(
            header,
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
    }

    #[test]
    fn parse_example_response() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xf8\
                         \x00\x04]\xb8\xd8\"";
        let header = Header::parse(response).unwrap();
        assert_eq!(
            header,
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
    }
}
