use core::fmt;

use crate::error::SampError;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlockNumber(u32);

impl BlockNumber {
    pub const ZERO: Self = Self(0);

    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    pub fn try_from_u64(n: u64) -> Result<Self, SampError> {
        u32::try_from(n)
            .map(Self)
            .map_err(|_| SampError::BlockNumberOverflow(n))
    }
}

impl fmt::Debug for BlockNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ExtIndex(u16);

impl ExtIndex {
    pub const ZERO: Self = Self(0);

    pub const fn new(i: u16) -> Self {
        Self(i)
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    pub fn try_from_usize(n: usize) -> Result<Self, SampError> {
        u16::try_from(n)
            .map(Self)
            .map_err(|_| SampError::ExtIndexOverflow(n))
    }
}

impl fmt::Debug for ExtIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, ".{}", self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlockRef {
    pub block: u32,
    pub index: u16,
}

impl BlockRef {
    pub const ZERO: Self = Self { block: 0, index: 0 };

    pub const fn new(block: u32, index: u16) -> Self {
        Self { block, index }
    }

    pub const fn is_zero(self) -> bool {
        self.block == 0 && self.index == 0
    }
}

impl fmt::Debug for BlockRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}.{}", self.block, self.index)
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Pubkey([u8; 32]);

impl Pubkey {
    pub const ZERO: Self = Self([0u8; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_compressed_ristretto(&self) -> curve25519_dalek::ristretto::CompressedRistretto {
        curve25519_dalek::ristretto::CompressedRistretto(self.0)
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pubkey(0x")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(0x")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct GenesisHash([u8; 32]);

impl GenesisHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for GenesisHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenesisHash(0x")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlockHash(0x")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct Nonce([u8; 12]);

impl Nonce {
    pub const ZERO: Self = Self([0u8; 12]);

    pub const fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 12] {
        self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nonce(0x")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}
