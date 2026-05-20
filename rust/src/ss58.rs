use blake2::Digest;

use crate::error::SampError;
use crate::types::{Pubkey, Ss58Address, Ss58Prefix};

pub fn encode(pubkey: &Pubkey, prefix: Ss58Prefix) -> Ss58Address {
    let prefix_bytes = encode_prefix(prefix);
    let mut payload = Vec::with_capacity(prefix_bytes.len() + 34);
    payload.extend_from_slice(&prefix_bytes);
    payload.extend_from_slice(pubkey.as_bytes());
    let mut hasher = blake2::Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(&payload);
    let hash = hasher.finalize();
    payload.extend_from_slice(&hash[..2]);
    let s = bs58_encode(&payload);
    Ss58Address::from_parts(s, *pubkey, prefix)
}

pub fn decode(address: &str) -> Result<Ss58Address, SampError> {
    let decoded = bs58_decode(address).map_err(|()| SampError::Ss58InvalidBase58)?;
    if decoded.len() < 35 {
        return Err(SampError::Ss58TooShort);
    }
    let (prefix_value, prefix_len) = decode_prefix(&decoded)?;
    let pubkey_end = prefix_len + 32;
    if decoded.len() < pubkey_end + 2 {
        return Err(SampError::Ss58TooShort);
    }
    if decoded.len() != pubkey_end + 2 {
        return Err(SampError::Ss58BadChecksum);
    }
    let payload = &decoded[..pubkey_end];
    let expected_checksum = &decoded[pubkey_end..pubkey_end + 2];
    let mut hasher = blake2::Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(payload);
    let hash = hasher.finalize();
    if &hash[..2] != expected_checksum {
        return Err(SampError::Ss58BadChecksum);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&decoded[prefix_len..pubkey_end]);
    let prefix = Ss58Prefix::new(prefix_value)?;
    Ok(Ss58Address::from_parts(
        address.to_string(),
        Pubkey::from_bytes(pk),
        prefix,
    ))
}

fn encode_prefix(prefix: Ss58Prefix) -> Vec<u8> {
    let value = prefix.get();
    if value < 64 {
        return vec![value as u8];
    }
    vec![
        (((value & 0b0000_0000_1111_1100) >> 2) as u8) | 0b0100_0000,
        ((value >> 8) as u8) | (((value & 0b0000_0000_0000_0011) as u8) << 6),
    ]
}

fn decode_prefix(decoded: &[u8]) -> Result<(u16, usize), SampError> {
    let first = decoded[0];
    if first & 0b1000_0000 != 0 {
        return Err(SampError::Ss58PrefixUnsupported(u16::from(first)));
    }
    if first & 0b0100_0000 == 0 {
        return Ok((u16::from(first), 1));
    }
    if decoded.len() < 2 {
        return Err(SampError::Ss58TooShort);
    }
    let second = decoded[1];
    let value = (u16::from(first & 0b0011_1111) << 2)
        | (u16::from(second >> 6))
        | (u16::from(second & 0b0011_1111) << 8);
    Ok((value, 2))
}

fn bs58_decode(input: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes = vec![0u8];
    for c in input.chars() {
        let byte = u8::try_from(u32::from(c)).map_err(|_| ())?;
        let idx = ALPHABET.iter().position(|&a| a == byte).ok_or(())?;
        let mut carry = idx;
        for b in bytes.iter_mut() {
            carry += usize::from(*b) * 58;
            *b = u8::try_from(carry % 256).unwrap_or(0);
            carry /= 256;
        }
        while carry > 0 {
            bytes.push(u8::try_from(carry % 256).unwrap_or(0));
            carry /= 256;
        }
    }
    for c in input.chars() {
        if c == '1' {
            bytes.push(0);
        } else {
            break;
        }
    }
    bytes.reverse();
    Ok(bytes)
}

fn bs58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if data.is_empty() {
        return String::new();
    }
    let mut digits = vec![0u32];
    for &byte in data {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            carry += *d * 256;
            *d = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let mut result = String::new();
    for &b in data {
        if b == 0 {
            result.push(char::from(ALPHABET[0]));
        } else {
            break;
        }
    }
    for &d in digits.iter().rev() {
        result.push(char::from(ALPHABET[d as usize]));
    }
    result
}
