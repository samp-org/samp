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
    block: BlockNumber,
    index: ExtIndex,
}

impl BlockRef {
    pub const ZERO: Self = Self {
        block: BlockNumber::ZERO,
        index: ExtIndex::ZERO,
    };

    pub const fn new(block: BlockNumber, index: ExtIndex) -> Self {
        Self { block, index }
    }

    pub const fn from_parts(block: u32, index: u16) -> Self {
        Self::new(BlockNumber::new(block), ExtIndex::new(index))
    }

    pub const fn block(self) -> BlockNumber {
        self.block
    }

    pub const fn index(self) -> ExtIndex {
        self.index
    }

    pub const fn is_zero(self) -> bool {
        self.block.get() == 0 && self.index.get() == 0
    }
}

impl fmt::Debug for BlockRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}.{}", self.block.get(), self.index.get())
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

    pub fn to_ss58(&self, prefix: Ss58Prefix) -> Ss58Address {
        Ss58Address::encode(self, prefix)
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ViewTag(u8);

impl ViewTag {
    pub const fn new(b: u8) -> Self {
        Self(b)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for ViewTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ViewTag(0x{:02x})", self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext({} bytes)", self.0.len())
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext({} bytes)", self.0.len())
    }
}

const CAPSULE_SIZE: usize = 33;

#[derive(Clone, PartialEq, Eq, Default)]
pub struct Capsules(Vec<u8>);

impl Capsules {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SampError> {
        if !bytes.len().is_multiple_of(CAPSULE_SIZE) {
            return Err(SampError::InvalidCapsules(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn count(&self) -> usize {
        self.0.len() / CAPSULE_SIZE
    }
}

impl fmt::Debug for Capsules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Capsules({} entries)", self.count())
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct RemarkBytes(Vec<u8>);

impl RemarkBytes {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for RemarkBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RemarkBytes({} bytes)", self.0.len())
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct ExtrinsicBytes(Vec<u8>);

impl ExtrinsicBytes {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ExtrinsicBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtrinsicBytes({} bytes)", self.0.len())
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ChannelName(String);

impl ChannelName {
    pub fn parse(s: impl Into<String>) -> Result<Self, SampError> {
        let s = s.into();
        if s.is_empty() || s.len() > crate::wire::CHANNEL_NAME_MAX {
            return Err(SampError::InvalidChannelName);
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ChannelName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelName({:?})", self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct ChannelDescription(String);

impl ChannelDescription {
    pub fn parse(s: impl Into<String>) -> Result<Self, SampError> {
        let s = s.into();
        if s.len() > crate::wire::CHANNEL_DESC_MAX {
            return Err(SampError::InvalidChannelDesc);
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ChannelDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelDescription({:?})", self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ss58Prefix(u16);

impl Ss58Prefix {
    pub const SUBSTRATE_GENERIC: Self = Self(42);
    pub const POLKADOT: Self = Self(0);
    pub const KUSAMA: Self = Self(2);

    pub fn new(value: u16) -> Result<Self, SampError> {
        if value > 63 {
            return Err(SampError::Ss58PrefixUnsupported(value));
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Debug for Ss58Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ss58Prefix({})", self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ss58Address {
    address: String,
    pubkey: Pubkey,
    prefix: Ss58Prefix,
}

impl Ss58Address {
    pub fn parse(s: &str) -> Result<Self, SampError> {
        crate::ss58::decode(s)
    }

    pub fn encode(pubkey: &Pubkey, prefix: Ss58Prefix) -> Self {
        crate::ss58::encode(pubkey, prefix)
    }

    pub(crate) fn from_parts(address: String, pubkey: Pubkey, prefix: Ss58Prefix) -> Self {
        Self {
            address,
            pubkey,
            prefix,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.address
    }

    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }

    pub fn prefix(&self) -> Ss58Prefix {
        self.prefix
    }

}

impl fmt::Debug for Ss58Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ss58Address({})", self.address)
    }
}

impl fmt::Display for Ss58Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.address)
    }
}

