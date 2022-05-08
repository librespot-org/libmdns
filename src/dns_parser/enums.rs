use super::Error;

/// The TYPE value according to RFC 1035
///
/// All "EXPERIMENTAL" markers here are from the RFC
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Type {
    /// a host addresss
    A = 1,
    /// an authoritative name server
    NS = 2,
    /// a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// a mail group member (EXPERIMENTAL)
    MG = 8,
    /// a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// a null RR (EXPERIMENTAL)
    NULL = 10,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
    /// IPv6 host address (RFC 2782)
    AAAA = 28,
    /// service record (RFC 2782)
    SRV = 33,
    /// EDNS0 options (RFC 6891)
    OPT = 41,
    /// Delegation signer (RFC 4034)
    DS = 43,
    /// DNSSEC signature (RFC 4034)
    RRSIG = 46,
    /// DNSEC options (RFC 4034)
    NSEC = 47,
    /// DNS Key record (RFC 4034)
    DNSKEY = 48,
}

/// The QTYPE value according to RFC 1035
///
/// All "EXPERIMENTAL" markers here are from the RFC
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum QueryType {
    /// a host addresss
    A = 1,
    /// an authoritative name server
    NS = 2,
    /// a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// a mail group member (EXPERIMENTAL)
    MG = 8,
    /// a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// a null RR (EXPERIMENTAL)
    NULL = 10,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
    /// IPv6 host address (RFC 2782)
    AAAA = 28,
    /// service record (RFC 2782)
    SRV = 33,
    /// A request for a transfer of an entire zone
    AXFR = 252,
    /// A request for mailbox-related records (MB, MG or MR)
    MAILB = 253,
    /// A request for mail agent RRs (Obsolete - see MX)
    MAILA = 254,
    /// A request for all records
    All = 255,
}

/// The CLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Class {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
}

/// The QCLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum QueryClass {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
    /// Any class
    Any = 255,
}

/// The OPCODE value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Opcode {
    StandardQuery,
    InverseQuery,
    ServerStatusRequest,
    Reserved(u16),
}

/// The RCODE value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u8),
}

impl From<u16> for Opcode {
    fn from(code: u16) -> Opcode {
        use self::Opcode::*;
        match code {
            0 => StandardQuery,
            1 => InverseQuery,
            2 => ServerStatusRequest,
            x => Reserved(x),
        }
    }
}
impl Into<u16> for Opcode {
    fn into(self) -> u16 {
        use self::Opcode::*;
        match self {
            StandardQuery => 0,
            InverseQuery => 1,
            ServerStatusRequest => 2,
            Reserved(x) => x,
        }
    }
}

impl From<u8> for ResponseCode {
    fn from(code: u8) -> ResponseCode {
        use self::ResponseCode::*;
        match code {
            0 => NoError,
            1 => FormatError,
            2 => ServerFailure,
            3 => NameError,
            4 => NotImplemented,
            5 => Refused,
            6..=15 => Reserved(code),
            x => panic!("Invalid response code {}", x),
        }
    }
}
impl Into<u8> for ResponseCode {
    fn into(self) -> u8 {
        use self::ResponseCode::*;
        match self {
            NoError => 0,
            FormatError => 1,
            ServerFailure => 2,
            NameError => 3,
            NotImplemented => 4,
            Refused => 5,
            Reserved(code) => code,
        }
    }
}

impl QueryType {
    pub fn parse(code: u16) -> Result<QueryType, Error> {
        use self::QueryType::*;
        match code {
            1 => Ok(A),
            2 => Ok(NS),
            4 => Ok(MF),
            5 => Ok(CNAME),
            6 => Ok(SOA),
            7 => Ok(MB),
            8 => Ok(MG),
            9 => Ok(MR),
            10 => Ok(NULL),
            11 => Ok(WKS),
            12 => Ok(PTR),
            13 => Ok(HINFO),
            14 => Ok(MINFO),
            15 => Ok(MX),
            16 => Ok(TXT),
            28 => Ok(AAAA),
            33 => Ok(SRV),
            252 => Ok(AXFR),
            253 => Ok(MAILB),
            254 => Ok(MAILA),
            255 => Ok(All),
            x => Err(Error::InvalidQueryType(x)),
        }
    }
}

impl QueryClass {
    pub fn parse(code: u16) -> Result<QueryClass, Error> {
        use self::QueryClass::*;
        match code {
            1 => Ok(IN),
            2 => Ok(CS),
            3 => Ok(CH),
            4 => Ok(HS),
            255 => Ok(Any),
            x => Err(Error::InvalidQueryClass(x)),
        }
    }
}

impl Type {
    pub fn parse(code: u16) -> Result<Type, Error> {
        use self::Type::*;
        match code {
            1 => Ok(A),
            2 => Ok(NS),
            4 => Ok(MF),
            5 => Ok(CNAME),
            6 => Ok(SOA),
            7 => Ok(MB),
            8 => Ok(MG),
            9 => Ok(MR),
            10 => Ok(NULL),
            11 => Ok(WKS),
            12 => Ok(PTR),
            13 => Ok(HINFO),
            14 => Ok(MINFO),
            15 => Ok(MX),
            16 => Ok(TXT),
            28 => Ok(AAAA),
            33 => Ok(SRV),
            41 => Ok(OPT),
            43 => Ok(DS),
            46 => Ok(RRSIG),
            47 => Ok(NSEC),
            48 => Ok(DNSKEY),
            x => Err(Error::InvalidType(x)),
        }
    }
}

impl Class {
    pub fn parse(code: u16) -> Result<Class, Error> {
        use self::Class::*;
        match code {
            1 => Ok(IN),
            2 => Ok(CS),
            3 => Ok(CH),
            4 => Ok(HS),
            x => Err(Error::InvalidClass(x)),
        }
    }
}
