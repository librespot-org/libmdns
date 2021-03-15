use thiserror::Error;

/// Error parsing DNS packet
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum Error {
    #[error("packet is smaller than header size")]
    HeaderTooShort,
    #[error("packet is has incomplete data")]
    UnexpectedEOF,
    #[error("wrong (too short or too long) size of RDATA")]
    WrongRdataLength,
    #[error("packet has non-zero reserved bits")]
    ReservedBitsAreNonZero,
    #[error("label in domain name has unknown label format")]
    UnknownLabelFormat,
    #[error("query type {0} is invalid")]
    InvalidQueryType(u16),
    #[error("query class {0} is invalid")]
    InvalidQueryClass(u16),
    #[error("type {0} is invalid")]
    InvalidType(u16),
    #[error("class {0} is invalid")]
    InvalidClass(u16),
    #[error("invalid characters encountered while reading label")]
    LabelIsNotAscii,
    #[error("parser is in the wrong state")]
    WrongState,
}
