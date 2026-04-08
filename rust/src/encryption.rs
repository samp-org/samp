use crate::error::SampError;
use crate::secret::Seed;
use crate::types::{Nonce, Pubkey};
use crate::wire::{EncryptedPayload, CAPSULE_SIZE};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use sha2::Sha256;
use zeroize::Zeroize;

pub type GroupEncrypted = (Pubkey, Vec<u8>, Vec<u8>);

const MESSAGE_KEY_INFO: &[u8] = b"samp-message";
const VIEW_TAG_INFO: &[u8] = b"samp-view-tag";
const SEAL_INFO: &[u8] = b"samp-seal";
const GROUP_EPH_INFO: &[u8] = b"samp-group-eph";
const KEY_WRAP_INFO: &[u8] = b"samp-key-wrap";

pub const ENCRYPTED_OVERHEAD: usize = 80;

// Shared primitives (Section 5.1-5.3)

pub fn sr25519_signing_scalar(seed: &Seed) -> Scalar {
    let msk = MiniSecretKey::from_bytes(seed.expose_secret()).expect("valid 32-byte seed");
    let secret = msk.expand(ExpansionMode::Ed25519);
    let mut scalar_bytes: [u8; 32] = secret.to_bytes()[..32].try_into().unwrap();
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    scalar_bytes.zeroize();
    scalar
}

pub fn public_from_seed(seed: &Seed) -> Pubkey {
    let scalar = sr25519_signing_scalar(seed);
    Pubkey::from_bytes(
        (scalar * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
    )
}

fn derive_view_tag(shared_secret: &[u8; 32]) -> u8 {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut tag = [0u8; 1];
    hk.expand(VIEW_TAG_INFO, &mut tag).expect("valid HKDF");
    tag[0]
}

fn ecdh_shared_secret(scalar: &Scalar, point: &CompressedRistretto) -> Result<[u8; 32], SampError> {
    let p = point.decompress().ok_or(SampError::DecryptionFailed)?;
    Ok((scalar * p).compress().to_bytes())
}

fn derive_symmetric_key(shared_secret: &[u8; 32], nonce: &Nonce) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce.as_bytes()), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(MESSAGE_KEY_INFO, &mut key).expect("valid HKDF");
    key
}

// 1:1 Encryption (Section 5.6) -- used by 0x11/0x12

fn derive_ephemeral(seed: &Seed, recipient: &[u8; 32], nonce: &Nonce) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed.expose_secret());
    let mut info = [0u8; 44];
    info[..32].copy_from_slice(recipient);
    info[32..].copy_from_slice(nonce.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("valid HKDF");
    okm
}

fn derive_seal_key(seed: &Seed, nonce: &Nonce) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce.as_bytes()), seed.expose_secret());
    let mut key = [0u8; 32];
    hk.expand(SEAL_INFO, &mut key).expect("valid HKDF");
    key
}

fn seal_recipient(recipient: &[u8; 32], sender_seed: &Seed, nonce: &Nonce) -> [u8; 32] {
    let key = derive_seal_key(sender_seed, nonce);
    let mut sealed = [0u8; 32];
    for i in 0..32 {
        sealed[i] = recipient[i] ^ key[i];
    }
    sealed
}

pub fn compute_view_tag(
    sender_seed: &Seed,
    recipient_pubkey: &Pubkey,
    nonce: &Nonce,
) -> Result<u8, SampError> {
    let recipient_point = recipient_pubkey.to_compressed_ristretto();
    let eph_bytes = derive_ephemeral(sender_seed, recipient_pubkey.as_bytes(), nonce);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let shared = ecdh_shared_secret(&eph_scalar, &recipient_point)?;
    Ok(derive_view_tag(&shared))
}

fn ensure_payload_size(payload: &EncryptedPayload) -> Result<(), SampError> {
    if payload.encrypted_content.len() < ENCRYPTED_OVERHEAD {
        return Err(SampError::InsufficientData);
    }
    Ok(())
}

pub fn check_view_tag(payload: &EncryptedPayload, signing_scalar: &Scalar) -> Result<u8, SampError> {
    ensure_payload_size(payload)?;
    let eph_pubkey = CompressedRistretto(payload.encrypted_content[..32].try_into().unwrap());
    let shared = ecdh_shared_secret(signing_scalar, &eph_pubkey)?;
    Ok(derive_view_tag(&shared))
}

pub fn unseal_recipient(payload: &EncryptedPayload, sender_seed: &Seed) -> Result<Pubkey, SampError> {
    ensure_payload_size(payload)?;
    let sealed_to: [u8; 32] = payload.encrypted_content[32..64].try_into().unwrap();
    let key = derive_seal_key(sender_seed, &payload.nonce);
    let mut recipient = [0u8; 32];
    for i in 0..32 {
        recipient[i] = sealed_to[i] ^ key[i];
    }
    Ok(Pubkey::from_bytes(recipient))
}

pub fn encrypt(
    plaintext: &[u8],
    recipient_pubkey: &Pubkey,
    nonce: &Nonce,
    sender_seed: &Seed,
) -> Result<Vec<u8>, SampError> {
    let recipient_point = recipient_pubkey.to_compressed_ristretto();
    let recipient_bytes = *recipient_pubkey.as_bytes();
    let mut eph_bytes = derive_ephemeral(sender_seed, &recipient_bytes, nonce);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();
    let mut shared_secret = ecdh_shared_secret(&eph_scalar, &recipient_point)?;

    let mut sealed_to = seal_recipient(&recipient_bytes, sender_seed, nonce);

    let mut sym_key = derive_symmetric_key(&shared_secret, nonce);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let ciphertext_with_tag = cipher
        .encrypt(
            ChaChaNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad: &sealed_to,
            },
        )
        .map_err(|_| SampError::DecryptionFailed)?;

    let mut content = Vec::with_capacity(ENCRYPTED_OVERHEAD + plaintext.len());
    content.extend_from_slice(&eph_pubkey.to_bytes());
    content.extend_from_slice(&sealed_to);
    content.extend_from_slice(&ciphertext_with_tag);

    eph_bytes.zeroize();
    shared_secret.zeroize();
    sealed_to.zeroize();
    sym_key.zeroize();
    Ok(content)
}

pub fn decrypt(payload: &EncryptedPayload, signing_scalar: &Scalar) -> Result<Vec<u8>, SampError> {
    ensure_payload_size(payload)?;
    let content = payload.encrypted_content.as_slice();
    let eph_pubkey = CompressedRistretto(content[..32].try_into().unwrap());
    let sealed_to: [u8; 32] = content[32..64].try_into().unwrap();
    let mut shared_secret = ecdh_shared_secret(signing_scalar, &eph_pubkey)?;
    let mut sym_key = derive_symmetric_key(&shared_secret, &payload.nonce);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let result = cipher
        .decrypt(
            ChaChaNonce::from_slice(payload.nonce.as_bytes()),
            Payload {
                msg: &content[64..],
                aad: &sealed_to,
            },
        )
        .map_err(|_| SampError::DecryptionFailed);
    shared_secret.zeroize();
    sym_key.zeroize();
    result
}

pub fn decrypt_as_sender(
    payload: &EncryptedPayload,
    sender_seed: &Seed,
) -> Result<Vec<u8>, SampError> {
    ensure_payload_size(payload)?;
    let content = payload.encrypted_content.as_slice();
    let sealed_to: [u8; 32] = content[32..64].try_into().unwrap();
    let mut recipient_bytes = seal_recipient(&sealed_to, sender_seed, &payload.nonce);
    let recipient_pubkey = CompressedRistretto(recipient_bytes);
    let mut eph_bytes = derive_ephemeral(sender_seed, &recipient_bytes, &payload.nonce);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let mut shared_secret = ecdh_shared_secret(&eph_scalar, &recipient_pubkey)?;
    let mut sym_key = derive_symmetric_key(&shared_secret, &payload.nonce);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let result = cipher
        .decrypt(
            ChaChaNonce::from_slice(payload.nonce.as_bytes()),
            Payload {
                msg: &content[64..],
                aad: &sealed_to,
            },
        )
        .map_err(|_| SampError::DecryptionFailed);
    recipient_bytes.zeroize();
    eph_bytes.zeroize();
    shared_secret.zeroize();
    sym_key.zeroize();
    result
}

// Multi-Recipient Encryption (Section 5.7) -- used by 0x15 (group)

pub fn derive_group_ephemeral(sender_seed: &Seed, nonce: &Nonce) -> Scalar {
    let hk = Hkdf::<Sha256>::new(None, sender_seed.expose_secret());
    let mut info = Vec::with_capacity(GROUP_EPH_INFO.len() + 12);
    info.extend_from_slice(GROUP_EPH_INFO);
    info.extend_from_slice(nonce.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("valid HKDF");
    let scalar = Scalar::from_bytes_mod_order(okm);
    okm.zeroize();
    scalar
}

fn derive_key_wrap(shared_secret: &[u8; 32], nonce: &Nonce) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce.as_bytes()), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(KEY_WRAP_INFO, &mut key).expect("valid HKDF");
    key
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

pub fn build_capsules(
    content_key: &[u8; 32],
    member_pubkeys: &[Pubkey],
    eph_scalar: &Scalar,
    nonce: &Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(member_pubkeys.len() * CAPSULE_SIZE);
    for pubkey in member_pubkeys {
        let point = pubkey.to_compressed_ristretto();
        let mut shared = match ecdh_shared_secret(eph_scalar, &point) {
            Ok(s) => s,
            Err(_) => {
                out.extend_from_slice(&[0u8; CAPSULE_SIZE]);
                continue;
            }
        };
        let tag = derive_view_tag(&shared);
        let mut kek = derive_key_wrap(&shared, nonce);
        let wrapped = xor32(content_key, &kek);
        out.push(tag);
        out.extend_from_slice(&wrapped);
        shared.zeroize();
        kek.zeroize();
    }
    out
}

pub fn scan_capsules(
    data: &[u8],
    eph_pubkey: &Pubkey,
    my_scalar: &Scalar,
    nonce: &Nonce,
) -> Option<(usize, [u8; 32])> {
    let eph_point = eph_pubkey.to_compressed_ristretto();
    let mut shared = ecdh_shared_secret(my_scalar, &eph_point).ok()?;
    let my_tag = derive_view_tag(&shared);
    let mut kek = derive_key_wrap(&shared, nonce);

    let mut offset = 0;
    let mut idx = 0;
    while offset + CAPSULE_SIZE <= data.len() {
        let tag = data[offset];
        if tag == my_tag {
            let mut wrapped = [0u8; 32];
            wrapped.copy_from_slice(&data[offset + 1..offset + 33]);
            let content_key = xor32(&wrapped, &kek);
            shared.zeroize();
            kek.zeroize();
            return Some((idx, content_key));
        }
        offset += CAPSULE_SIZE;
        idx += 1;
    }
    shared.zeroize();
    kek.zeroize();
    None
}

pub fn encrypt_for_group(
    plaintext: &[u8],
    member_pubkeys: &[Pubkey],
    nonce: &Nonce,
    sender_seed: &Seed,
) -> Result<GroupEncrypted, SampError> {
    let eph_scalar = derive_group_ephemeral(sender_seed, nonce);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();

    let mut content_key = [0u8; 32];
    getrandom::fill(&mut content_key).map_err(|_| SampError::DecryptionFailed)?;

    let capsules = build_capsules(&content_key, member_pubkeys, &eph_scalar, nonce);

    let cipher = ChaCha20Poly1305::new((&content_key).into());
    let ciphertext = cipher
        .encrypt(ChaChaNonce::from_slice(nonce.as_bytes()), plaintext)
        .map_err(|_| SampError::DecryptionFailed)?;

    content_key.zeroize();
    Ok((Pubkey::from_bytes(eph_pubkey.to_bytes()), capsules, ciphertext))
}

pub fn decrypt_from_group(
    content: &[u8],
    my_scalar: &Scalar,
    nonce: &Nonce,
    known_member_count: Option<usize>,
) -> Result<Vec<u8>, SampError> {
    if content.len() < 32 {
        return Err(SampError::InsufficientData);
    }
    let eph_pubkey = Pubkey::from_bytes(content[..32].try_into().unwrap());
    let after_eph = &content[32..];

    let (capsule_idx, mut content_key) = scan_capsules(after_eph, &eph_pubkey, my_scalar, nonce)
        .ok_or(SampError::DecryptionFailed)?;

    let cipher = ChaCha20Poly1305::new((&content_key).into());

    if let Some(n) = known_member_count {
        let ct_start = n * CAPSULE_SIZE;
        if ct_start > after_eph.len() {
            content_key.zeroize();
            return Err(SampError::InsufficientData);
        }
        let result = cipher
            .decrypt(ChaChaNonce::from_slice(nonce.as_bytes()), &after_eph[ct_start..])
            .map_err(|_| SampError::DecryptionFailed);
        content_key.zeroize();
        return result;
    }

    let min_n = capsule_idx + 1;
    let max_n = (after_eph.len().saturating_sub(16)) / CAPSULE_SIZE;
    for n in min_n..=max_n {
        let ct_start = n * CAPSULE_SIZE;
        if ct_start >= after_eph.len() {
            break;
        }
        if let Ok(plaintext) =
            cipher.decrypt(ChaChaNonce::from_slice(nonce.as_bytes()), &after_eph[ct_start..])
        {
            content_key.zeroize();
            return Ok(plaintext);
        }
    }
    content_key.zeroize();
    Err(SampError::DecryptionFailed)
}
