use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SampError {
    InvalidVersion(u8),
    ReservedContentType(u8),
    DecryptionFailed,
    InvalidUtf8,
    InsufficientData,
    InvalidChannelName,
    InvalidChannelDesc,
    BlockNumberOverflow(u64),
    ExtIndexOverflow(usize),
    InvalidCapsules(usize),
    Ss58PrefixUnsupported(u16),
    Ss58InvalidBase58,
    Ss58TooShort,
    Ss58BadChecksum,
}

impl fmt::Display for SampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(v) => write!(f, "unsupported version: 0x{v:02x}"),
            Self::ReservedContentType(ct) => write!(f, "reserved content type: 0x{ct:02x}"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::InvalidUtf8 => write!(f, "content is not valid UTF-8"),
            Self::InsufficientData => write!(f, "insufficient data"),
            Self::InvalidChannelName => write!(f, "channel name must be 1-32 bytes"),
            Self::InvalidChannelDesc => write!(f, "channel description must be 0-128 bytes"),
            Self::BlockNumberOverflow(n) => write!(f, "block number {n} exceeds u32::MAX"),
            Self::ExtIndexOverflow(n) => write!(f, "ext index {n} exceeds u16::MAX"),
            Self::InvalidCapsules(n) => write!(f, "capsules length {n} not a multiple of 33"),
            Self::Ss58PrefixUnsupported(p) => {
                write!(f, "SS58 prefix {p} requires two-byte encoding (unsupported)")
            }
            Self::Ss58InvalidBase58 => write!(f, "SS58 address contains invalid base58"),
            Self::Ss58TooShort => write!(f, "SS58 address too short"),
            Self::Ss58BadChecksum => write!(f, "SS58 address has invalid checksum"),
        }
    }
}

impl std::error::Error for SampError {}
