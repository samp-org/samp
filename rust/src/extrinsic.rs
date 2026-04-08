use blake2::Digest;
use parity_scale_codec::{Compact, Encode};

use crate::scale;
use crate::types::{ExtrinsicBytes, GenesisHash, Pubkey, Signature};

const EXT_VERSION_SIGNED: u8 = 0x84;
const ADDR_TYPE_ID: u8 = 0x00;
const SIG_TYPE_SR25519: u8 = 0x01;
const ERA_IMMORTAL: u8 = 0x00;
const METADATA_HASH_DISABLED: u8 = 0x00;
const SIGNED_HEADER_LEN: usize = 99;
const MIN_SIGNED_EXTRINSIC: usize = 103;
const MIN_SIGNER_PAYLOAD: usize = 34;

#[derive(Clone, Debug)]
pub struct ChainParams {
    pub genesis_hash: GenesisHash,
    pub spec_version: u32,
    pub tx_version: u32,
}

#[derive(Debug, Clone)]
pub enum Error {
    CallTooLarge { len: usize },
    PayloadTooLarge { len: usize },
    Malformed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CallTooLarge { len } => write!(f, "call args too large: {len} bytes"),
            Self::PayloadTooLarge { len } => write!(f, "extrinsic payload too large: {len} bytes"),
            Self::Malformed => write!(f, "malformed extrinsic"),
        }
    }
}

impl std::error::Error for Error {}

pub fn build_signed_extrinsic(
    pallet_idx: u8,
    call_idx: u8,
    call_args: &[u8],
    public_key: &Pubkey,
    sign: impl Fn(&[u8]) -> Signature,
    nonce: u32,
    chain_params: &ChainParams,
) -> Result<ExtrinsicBytes, Error> {
    let _ = u32::try_from(call_args.len()).map_err(|_| Error::CallTooLarge {
        len: call_args.len(),
    })?;

    let mut call_data = Vec::with_capacity(2 + call_args.len());
    call_data.push(pallet_idx);
    call_data.push(call_idx);
    call_data.extend_from_slice(call_args);

    let tip: u8 = 0x00;

    let mut signing_payload = Vec::new();
    signing_payload.extend_from_slice(&call_data);
    signing_payload.push(ERA_IMMORTAL);
    Compact(nonce).encode_to(&mut signing_payload);
    signing_payload.push(tip);
    signing_payload.push(METADATA_HASH_DISABLED);
    signing_payload.extend_from_slice(&chain_params.spec_version.to_le_bytes());
    signing_payload.extend_from_slice(&chain_params.tx_version.to_le_bytes());
    signing_payload.extend_from_slice(chain_params.genesis_hash.as_bytes());
    signing_payload.extend_from_slice(chain_params.genesis_hash.as_bytes());
    signing_payload.push(0x00);

    let to_sign = if signing_payload.len() > 256 {
        let mut hasher = blake2::Blake2b::<blake2::digest::typenum::U32>::new();
        hasher.update(&signing_payload);
        hasher.finalize().to_vec()
    } else {
        signing_payload
    };

    let signature = sign(&to_sign);

    let mut extrinsic_payload = Vec::with_capacity(SIGNED_HEADER_LEN + 4 + call_data.len());
    extrinsic_payload.push(EXT_VERSION_SIGNED);
    extrinsic_payload.push(ADDR_TYPE_ID);
    extrinsic_payload.extend_from_slice(public_key.as_bytes());
    extrinsic_payload.push(SIG_TYPE_SR25519);
    extrinsic_payload.extend_from_slice(signature.as_bytes());
    extrinsic_payload.push(ERA_IMMORTAL);
    Compact(nonce).encode_to(&mut extrinsic_payload);
    extrinsic_payload.push(tip);
    extrinsic_payload.push(METADATA_HASH_DISABLED);
    extrinsic_payload.extend_from_slice(&call_data);

    let payload_len =
        u32::try_from(extrinsic_payload.len()).map_err(|_| Error::PayloadTooLarge {
            len: extrinsic_payload.len(),
        })?;

    let mut full = Vec::with_capacity(extrinsic_payload.len() + 5);
    Compact(payload_len).encode_to(&mut full);
    full.extend_from_slice(&extrinsic_payload);

    Ok(ExtrinsicBytes::from_bytes(full))
}

pub fn extract_signer(extrinsic_bytes: &ExtrinsicBytes) -> Option<Pubkey> {
    let bytes = extrinsic_bytes.as_bytes();
    let (_, prefix_len) = scale::decode_compact(bytes)?;
    let payload = &bytes[prefix_len..];
    if payload.len() < MIN_SIGNER_PAYLOAD || payload[0] & 0x80 == 0 || payload[1] != ADDR_TYPE_ID {
        return None;
    }
    let mut account = [0u8; 32];
    account.copy_from_slice(&payload[2..34]);
    Some(Pubkey::from_bytes(account))
}

pub struct ExtractedCall<'a> {
    pub pallet: u8,
    pub call: u8,
    pub args: &'a [u8],
}

pub fn extract_call<'a>(extrinsic_bytes: &'a ExtrinsicBytes) -> Option<ExtractedCall<'a>> {
    let bytes = extrinsic_bytes.as_bytes();
    let (_, prefix_len) = scale::decode_compact(bytes)?;
    let payload = &bytes[prefix_len..];

    if payload.len() < MIN_SIGNED_EXTRINSIC || payload[0] & 0x80 == 0 {
        return None;
    }

    let mut offset = SIGNED_HEADER_LEN;
    if offset >= payload.len() {
        return None;
    }
    if payload[offset] != 0x00 {
        offset += 2;
    } else {
        offset += 1;
    }
    let (_, nonce_len) = scale::decode_compact(&payload[offset..])?;
    offset += nonce_len;
    let (_, tip_len) = scale::decode_compact(&payload[offset..])?;
    offset += tip_len;
    offset += 1;

    if offset + 2 > payload.len() {
        return None;
    }
    let pallet = payload[offset];
    let call = payload[offset + 1];
    offset += 2;

    if offset > payload.len() {
        return None;
    }

    Some(ExtractedCall {
        pallet,
        call,
        args: &payload[offset..],
    })
}
