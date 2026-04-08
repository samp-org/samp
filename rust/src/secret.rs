use core::fmt;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Seed(Zeroizing<[u8; 32]>);

impl Seed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed([REDACTED])")
    }
}
