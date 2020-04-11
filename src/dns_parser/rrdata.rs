use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use super::{Error, Name, Type};

/// The enumeration that represents known types of DNS resource records data
#[derive(Debug, Clone)]
pub enum RRData<'a> {
    CNAME(Name<'a>),
    NS(Name<'a>),
    PTR(Name<'a>),
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name<'a>,
    },
    MX {
        preference: u16,
        exchange: Name<'a>,
    },
    TXT(&'a [u8]),
    // Anything that can't be parsed yet
    Unknown {
        typ: Type,
        data: &'a [u8],
    },
}

impl<'a> RRData<'a> {
    pub fn typ(&self) -> Type {
        match *self {
            RRData::CNAME(..) => Type::CNAME,
            RRData::NS(..) => Type::NS,
            RRData::PTR(..) => Type::PTR,
            RRData::A(..) => Type::A,
            RRData::AAAA(..) => Type::AAAA,
            RRData::SRV { .. } => Type::SRV,
            RRData::MX { .. } => Type::MX,
            RRData::TXT(..) => Type::TXT,
            RRData::Unknown { typ, .. } => typ,
        }
    }

    pub fn write_to<T: io::Write>(&self, writer: &mut T) -> io::Result<()> {
        match *self {
            RRData::CNAME(ref name) | RRData::NS(ref name) | RRData::PTR(ref name) => {
                name.write_to(writer)
            }

            RRData::A(ip) => writer.write_u32::<BigEndian>(ip.into()),

            RRData::AAAA(ip) => {
                for segment in ip.segments().iter() {
                    writer.write_u16::<BigEndian>(*segment)?;
                }
                Ok(())
            }
            RRData::SRV {
                priority,
                weight,
                port,
                ref target,
            } => {
                writer.write_u16::<BigEndian>(priority)?;
                writer.write_u16::<BigEndian>(weight)?;
                writer.write_u16::<BigEndian>(port)?;
                target.write_to(writer)
            }
            RRData::MX {
                preference,
                ref exchange,
            } => {
                writer.write_u16::<BigEndian>(preference)?;
                exchange.write_to(writer)
            }
            RRData::TXT(data) => writer.write_all(data),
            RRData::Unknown { data, .. } => writer.write_all(data),
        }
    }

    pub fn parse(typ: Type, rdata: &'a [u8], original: &'a [u8]) -> Result<RRData<'a>, Error> {
        match typ {
            Type::A => {
                if rdata.len() != 4 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::A(Ipv4Addr::from(BigEndian::read_u32(rdata))))
            }
            Type::AAAA => {
                if rdata.len() != 16 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::AAAA(Ipv6Addr::new(
                    BigEndian::read_u16(&rdata[0..2]),
                    BigEndian::read_u16(&rdata[2..4]),
                    BigEndian::read_u16(&rdata[4..6]),
                    BigEndian::read_u16(&rdata[6..8]),
                    BigEndian::read_u16(&rdata[8..10]),
                    BigEndian::read_u16(&rdata[10..12]),
                    BigEndian::read_u16(&rdata[12..14]),
                    BigEndian::read_u16(&rdata[14..16]),
                )))
            }
            Type::CNAME => Ok(RRData::CNAME(Name::scan(rdata, original)?.0)),
            Type::NS => Ok(RRData::NS(Name::scan(rdata, original)?.0)),
            Type::PTR => Ok(RRData::PTR(Name::scan(rdata, original)?.0)),
            Type::MX => {
                if rdata.len() < 3 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::MX {
                    preference: BigEndian::read_u16(&rdata[..2]),
                    exchange: Name::scan(&rdata[2..], original)?.0,
                })
            }
            Type::SRV => {
                if rdata.len() < 7 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::SRV {
                    priority: BigEndian::read_u16(&rdata[..2]),
                    weight: BigEndian::read_u16(&rdata[2..4]),
                    port: BigEndian::read_u16(&rdata[4..6]),
                    target: Name::scan(&rdata[6..], original)?.0,
                })
            }
            Type::TXT => Ok(RRData::TXT(rdata)),
            typ => Ok(RRData::Unknown {
                typ: typ,
                data: rdata,
            }),
        }
    }
}
