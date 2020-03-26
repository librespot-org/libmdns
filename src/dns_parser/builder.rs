use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use super::{Header, Name, Opcode, QueryClass, QueryType, RRData, ResponseCode};

pub enum Questions {}
pub enum Answers {}
#[allow(dead_code)]
pub enum Nameservers {}
pub enum Additional {}

pub trait MoveTo<T> {}
impl<T> MoveTo<T> for T {}

impl MoveTo<Answers> for Questions {}

impl MoveTo<Nameservers> for Questions {}
impl MoveTo<Nameservers> for Answers {}

impl MoveTo<Additional> for Questions {}
impl MoveTo<Additional> for Answers {}
impl MoveTo<Additional> for Nameservers {}

/// Allows to build a DNS packet
///
/// Both query and answer packets may be built with this interface, although,
/// much of functionality is not implemented yet.
pub struct Builder<S> {
    buf: Vec<u8>,
    max_size: Option<usize>,
    _state: PhantomData<S>,
}

impl Builder<Questions> {
    /// Creates a new query
    ///
    /// Initially all sections are empty. You're expected to fill
    /// the questions section with `add_question`
    #[allow(dead_code)]
    pub fn new_query(id: u16, recursion: bool) -> Builder<Questions> {
        let mut buf = Vec::with_capacity(512);
        let head = Header {
            id: id,
            query: true,
            opcode: Opcode::StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: recursion,
            recursion_available: false,
            response_code: ResponseCode::NoError,
            questions: 0,
            answers: 0,
            nameservers: 0,
            additional: 0,
        };
        buf.extend([0u8; 12].iter());
        head.write(&mut buf[..12]);
        Builder {
            buf: buf,
            max_size: Some(512),
            _state: PhantomData,
        }
    }

    pub fn new_response(id: u16, recursion: bool, authoritative: bool) -> Builder<Questions> {
        let mut buf = Vec::with_capacity(512);
        let head = Header {
            id: id,
            query: false,
            opcode: Opcode::StandardQuery,
            authoritative: authoritative,
            truncated: false,
            recursion_desired: recursion,
            recursion_available: false,
            response_code: ResponseCode::NoError,
            questions: 0,
            answers: 0,
            nameservers: 0,
            additional: 0,
        };
        buf.extend([0u8; 12].iter());
        head.write(&mut buf[..12]);
        Builder {
            buf: buf,
            max_size: Some(512),
            _state: PhantomData,
        }
    }
}

impl<T> Builder<T> {
    fn write_rr(&mut self, name: &Name, cls: QueryClass, ttl: u32, data: &RRData) {
        name.write_to(&mut self.buf).unwrap();
        self.buf.write_u16::<BigEndian>(data.typ() as u16).unwrap();
        self.buf.write_u16::<BigEndian>(cls as u16).unwrap();
        self.buf.write_u32::<BigEndian>(ttl).unwrap();

        let size_offset = self.buf.len();
        self.buf.write_u16::<BigEndian>(0).unwrap();

        let data_offset = self.buf.len();
        data.write_to(&mut self.buf).unwrap();
        let data_size = self.buf.len() - data_offset;

        BigEndian::write_u16(
            &mut self.buf[size_offset..size_offset + 2],
            data_size as u16,
        );
    }

    /// Returns the final packet
    ///
    /// When packet is not truncated method returns `Ok(packet)`. If
    /// packet is truncated the method returns `Err(packet)`. In both
    /// cases the packet is fully valid.
    ///
    /// In the server implementation you may use
    /// `x.build().unwrap_or_else(|x| x)`.
    ///
    /// In the client implementation it's probably unwise to send truncated
    /// packet, as it doesn't make sense. Even panicking may be more
    /// appropriate.
    // TODO(tailhook) does the truncation make sense for TCP, and how
    // to treat it for EDNS0?
    pub fn build(mut self) -> Result<Vec<u8>, Vec<u8>> {
        // TODO(tailhook) optimize labels
        match self.max_size {
            Some(max_size) if self.buf.len() > max_size => {
                Header::set_truncated(&mut self.buf[..12]);
                Err(self.buf)
            }
            _ => Ok(self.buf),
        }
    }

    pub fn move_to<U>(self) -> Builder<U>
    where
        T: MoveTo<U>,
    {
        Builder {
            buf: self.buf,
            max_size: self.max_size,
            _state: PhantomData,
        }
    }

    pub fn set_max_size(&mut self, max_size: Option<usize>) {
        self.max_size = max_size;
    }

    pub fn is_empty(&self) -> bool {
        Header::question_count(&self.buf) == 0
            && Header::answer_count(&self.buf) == 0
            && Header::nameserver_count(&self.buf) == 0
            && Header::additional_count(&self.buf) == 0
    }
}

impl<T: MoveTo<Questions>> Builder<T> {
    /// Adds a question to the packet
    ///
    /// # Panics
    ///
    /// * There are already 65535 questions in the buffer.
    #[allow(dead_code)]
    pub fn add_question(
        self,
        qname: &Name,
        qtype: QueryType,
        qclass: QueryClass,
    ) -> Builder<Questions> {
        let mut builder = self.move_to::<Questions>();

        qname.write_to(&mut builder.buf).unwrap();
        builder.buf.write_u16::<BigEndian>(qtype as u16).unwrap();
        builder.buf.write_u16::<BigEndian>(qclass as u16).unwrap();
        Header::inc_questions(&mut builder.buf).expect("Too many questions");
        builder
    }
}

impl<T: MoveTo<Answers>> Builder<T> {
    pub fn add_answer(
        self,
        name: &Name,
        cls: QueryClass,
        ttl: u32,
        data: &RRData,
    ) -> Builder<Answers> {
        let mut builder = self.move_to::<Answers>();

        builder.write_rr(name, cls, ttl, data);
        Header::inc_answers(&mut builder.buf).expect("Too many answers");

        builder
    }
}

impl<T: MoveTo<Nameservers>> Builder<T> {
    #[allow(dead_code)]
    pub fn add_nameserver(
        self,
        name: &Name,
        cls: QueryClass,
        ttl: u32,
        data: &RRData,
    ) -> Builder<Nameservers> {
        let mut builder = self.move_to::<Nameservers>();

        builder.write_rr(name, cls, ttl, data);
        Header::inc_nameservers(&mut builder.buf).expect("Too many nameservers");

        builder
    }
}

impl Builder<Additional> {
    #[allow(dead_code)]
    pub fn add_additional(
        self,
        name: &Name,
        cls: QueryClass,
        ttl: u32,
        data: &RRData,
    ) -> Builder<Additional> {
        let mut builder = self.move_to::<Additional>();

        builder.write_rr(name, cls, ttl, data);
        Header::inc_nameservers(&mut builder.buf).expect("Too many additional answers");

        builder
    }
}

#[cfg(test)]
mod test {
    use super::Builder;
    use super::Name;
    use super::QueryClass as QC;
    use super::QueryType as QT;

    #[test]
    fn build_query() {
        let mut bld = Builder::new_query(1573, true);
        let name = Name::from_str("example.com").unwrap();
        bld = bld.add_question(&name, QT::A, QC::IN);
        let result = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        assert_eq!(&bld.build().unwrap()[..], &result[..]);
    }

    #[test]
    fn build_srv_query() {
        let mut bld = Builder::new_query(23513, true);
        let name = Name::from_str("_xmpp-server._tcp.gmail.com").unwrap();
        bld = bld.add_question(&name, QT::SRV, QC::IN);
        let result = b"[\xd9\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
            \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01";
        assert_eq!(&bld.build().unwrap()[..], &result[..]);
    }
}
