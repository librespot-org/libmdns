use std::borrow::Cow;
use std::fmt;
use std::fmt::Write;
use std::hash;
use std::io;
use std::str::from_utf8;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use super::Error;

/// The DNS name as stored in the original packet
///
/// This is contains just a reference to a slice that contains the data.
/// You may turn this into a string using `.to_string()`
#[derive(Debug, Clone)]
pub enum Name<'a> {
    FromPacket {
        labels: &'a [u8],
        /// This is the original buffer size. The compressed names in original
        /// are calculated in this buffer
        original: &'a [u8],
    },

    FromStr(Cow<'a, str>),
}

impl<'a> Name<'a> {
    pub fn scan(data: &'a [u8], original: &'a [u8]) -> Result<(Name<'a>, usize), Error> {
        let mut pos = 0;
        loop {
            if data.len() <= pos {
                return Err(Error::UnexpectedEOF);
            }
            let byte = data[pos];
            if byte == 0 {
                #[allow(clippy::range_plus_one)]
                return Ok((
                    Self::FromPacket {
                        labels: &data[..pos + 1],
                        original,
                    },
                    pos + 1,
                ));
            } else if byte & 0b1100_0000 == 0b1100_0000 {
                if data.len() < pos + 2 {
                    return Err(Error::UnexpectedEOF);
                }
                let off =
                    (BigEndian::read_u16(&data[pos..pos + 2]) & !0b1100_0000_0000_0000) as usize;
                if off >= original.len() {
                    return Err(Error::UnexpectedEOF);
                }
                // Validate referred to location
                Self::scan(&original[off..], original)?;
                return Ok((
                    Self::FromPacket {
                        labels: &data[..pos + 2],
                        original,
                    },
                    pos + 2,
                ));
            } else if byte & 0b1100_0000 == 0 {
                let end = pos + byte as usize + 1;
                if end >= data.len() {
                    return Err(Error::UnexpectedEOF);
                }
                if from_utf8(&data[pos + 1..end]).is_err() {
                    return Err(Error::LabelIsNotAscii);
                }
                pos = end;
                if data.len() <= pos {
                    return Err(Error::UnexpectedEOF);
                }
            } else {
                return Err(Error::UnknownLabelFormat);
            }
        }
    }

    pub fn from_str<T: Into<Cow<'static, str>>>(name: T) -> Name<'a> {
        Self::FromStr(name.into())
    }

    pub fn write_to<T: io::Write>(&self, writer: &mut T) -> io::Result<()> {
        match *self {
            Self::FromPacket { labels, original } => {
                let mut pos = 0;
                loop {
                    let byte = labels[pos];
                    if byte == 0 {
                        writer.write_u8(0)?;
                        return Ok(());
                    } else if byte & 0b1100_0000 == 0b1100_0000 {
                        let off = (BigEndian::read_u16(&labels[pos..pos + 2])
                            & !0b1100_0000_0000_0000) as usize;
                        return Self::scan(&original[off..], original)
                            .unwrap()
                            .0
                            .write_to(writer);
                    } else if byte & 0b1100_0000 == 0 {
                        let end = pos + byte as usize + 1;
                        writer.write_all(&labels[pos..end])?;
                        pos = end;
                    } else {
                        unreachable!();
                    }
                }
            }

            Self::FromStr(ref name) => {
                for part in name.split('.') {
                    assert!(part.len() < 63);
                    #[allow(clippy::cast_possible_truncation)]
                    let ln = part.len() as u8;
                    writer.write_u8(ln)?;
                    writer.write_all(part.as_bytes())?;
                }
                writer.write_u8(0)?;

                Ok(())
            }
        }
    }
}

impl fmt::Display for Name<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::FromPacket { labels, original } => {
                let mut pos = 0;
                loop {
                    let byte = labels[pos];
                    if byte == 0 {
                        return Ok(());
                    } else if byte & 0b1100_0000 == 0b1100_0000 {
                        let off = (BigEndian::read_u16(&labels[pos..pos + 2])
                            & !0b1100_0000_0000_0000) as usize;
                        if pos != 0 {
                            fmt.write_char('.')?;
                        }
                        return fmt::Display::fmt(
                            &Self::scan(&original[off..], original).unwrap().0,
                            fmt,
                        );
                    } else if byte & 0b1100_0000 == 0 {
                        if pos != 0 {
                            fmt.write_char('.')?;
                        }
                        let end = pos + byte as usize + 1;
                        fmt.write_str(from_utf8(&labels[pos + 1..end]).unwrap())?;
                        pos = end;
                    } else {
                        unreachable!();
                    }
                }
            }

            Self::FromStr(ref name) => fmt.write_str(name),
        }
    }
}

impl hash::Hash for Name<'_> {
    fn hash<H>(&self, state: &mut H)
    where
        H: hash::Hasher,
    {
        let mut buffer = Vec::new();
        self.write_to(&mut buffer).unwrap();
        hash::Hash::hash(&buffer, state);
    }
}

impl PartialEq for Name<'_> {
    fn eq(&self, other: &Name<'_>) -> bool {
        let mut buffer = Vec::new();
        self.write_to(&mut buffer).unwrap();

        let mut other_buffer = Vec::new();
        other.write_to(&mut other_buffer).unwrap();

        buffer == other_buffer
    }
}

impl Eq for Name<'_> {}
