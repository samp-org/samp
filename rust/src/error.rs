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
        }
    }
}

impl std::error::Error for SampError {}
