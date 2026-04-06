use crate::error::SampError;
use crate::wire::CAPSULE_SIZE;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use sha2::Sha256;
use zeroize::Zeroize;

/// Ephemeral public key, capsules, ciphertext — returned by group encryption.
pub type GroupEncrypted = ([u8; 32], Vec<u8>, Vec<u8>);

const MESSAGE_KEY_INFO: &[u8] = b"samp-message-v1";
const VIEW_TAG_INFO: &[u8] = b"samp-view-tag-v1";
const SEAL_INFO: &[u8] = b"samp-seal-v1";
const GROUP_EPH_INFO: &[u8] = b"samp-group-eph";
const KEY_WRAP_INFO: &[u8] = b"samp-key-wrap-v1";

/// Encrypted 1:1 content overhead: ephemeral(32) + sealed_to(32) + auth_tag(16) = 80 bytes.
pub const ENCRYPTED_OVERHEAD: usize = 80;

// ---------------------------------------------------------------------------
// Shared primitives (Section 5.1-5.3)
// ---------------------------------------------------------------------------

pub fn sr25519_signing_scalar(seed: &[u8; 32]) -> Scalar {
    let msk = MiniSecretKey::from_bytes(seed).expect("valid 32-byte seed");
    let secret = msk.expand(ExpansionMode::Ed25519);
    let mut scalar_bytes: [u8; 32] = secret.to_bytes()[..32].try_into().unwrap();
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    scalar_bytes.zeroize();
    scalar
}

pub fn public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let scalar = sr25519_signing_scalar(seed);
    (scalar * RISTRETTO_BASEPOINT_POINT).compress().to_bytes()
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

fn derive_symmetric_key(shared_secret: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(MESSAGE_KEY_INFO, &mut key).expect("valid HKDF");
    key
}

// ---------------------------------------------------------------------------
// 1:1 Encryption (Section 5.6) -- used by 0x11/0x12
// ---------------------------------------------------------------------------

fn derive_ephemeral(seed: &[u8; 32], recipient: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut info = [0u8; 44];
    info[..32].copy_from_slice(recipient);
    info[32..].copy_from_slice(nonce);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("valid HKDF");
    okm
}

fn derive_seal_key(seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), seed);
    let mut key = [0u8; 32];
    hk.expand(SEAL_INFO, &mut key).expect("valid HKDF");
    key
}

fn seal_recipient(recipient: &[u8; 32], sender_seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let key = derive_seal_key(sender_seed, nonce);
    let mut sealed = [0u8; 32];
    for i in 0..32 {
        sealed[i] = recipient[i] ^ key[i];
    }
    sealed
}

/// Compute the view tag for an outbound 1:1 message.
pub fn compute_view_tag(
    sender_seed: &[u8; 32],
    recipient_pubkey: &CompressedRistretto,
    nonce: &[u8; 12],
) -> Result<u8, SampError> {
    let eph_bytes = derive_ephemeral(sender_seed, &recipient_pubkey.to_bytes(), nonce);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let shared = ecdh_shared_secret(&eph_scalar, recipient_pubkey)?;
    Ok(derive_view_tag(&shared))
}

/// Verify the view tag for an inbound 1:1 message.
pub fn check_view_tag(signing_scalar: &Scalar, encrypted_content: &[u8]) -> Result<u8, SampError> {
    if encrypted_content.len() < ENCRYPTED_OVERHEAD {
        return Err(SampError::InsufficientData);
    }
    let eph_pubkey = CompressedRistretto(encrypted_content[..32].try_into().unwrap());
    let shared = ecdh_shared_secret(signing_scalar, &eph_pubkey)?;
    Ok(derive_view_tag(&shared))
}

/// Recover the recipient pubkey from sealed_to (sender self-decryption).
pub fn unseal_recipient(
    encrypted_content: &[u8],
    sender_seed: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<[u8; 32], SampError> {
    if encrypted_content.len() < ENCRYPTED_OVERHEAD {
        return Err(SampError::InsufficientData);
    }
    let sealed_to: [u8; 32] = encrypted_content[32..64].try_into().unwrap();
    let key = derive_seal_key(sender_seed, nonce);
    let mut recipient = [0u8; 32];
    for i in 0..32 {
        recipient[i] = sealed_to[i] ^ key[i];
    }
    Ok(recipient)
}

/// Encrypt plaintext for a single recipient (1:1).
/// Content: ephemeral(32) || sealed_to(32) || ciphertext || auth_tag(16).
pub fn encrypt(
    plaintext: &[u8],
    recipient_pubkey: &CompressedRistretto,
    nonce: &[u8; 12],
    sender_seed: &[u8; 32],
) -> Result<Vec<u8>, SampError> {
    let recipient_bytes = recipient_pubkey.to_bytes();
    let mut eph_bytes = derive_ephemeral(sender_seed, &recipient_bytes, nonce);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();
    let mut shared_secret = ecdh_shared_secret(&eph_scalar, recipient_pubkey)?;

    let mut sealed_to = seal_recipient(&recipient_bytes, sender_seed, nonce);

    let mut sym_key = derive_symmetric_key(&shared_secret, nonce);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let ciphertext_with_tag = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
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

/// Decrypt as the recipient (1:1).
pub fn decrypt(
    content: &[u8],
    signing_scalar: &Scalar,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, SampError> {
    if content.len() < ENCRYPTED_OVERHEAD {
        return Err(SampError::InsufficientData);
    }
    let eph_pubkey = CompressedRistretto(content[..32].try_into().unwrap());
    let mut shared_secret = ecdh_shared_secret(signing_scalar, &eph_pubkey)?;
    let mut sym_key = derive_symmetric_key(&shared_secret, nonce);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let result = cipher
        .decrypt(Nonce::from_slice(nonce), &content[64..])
        .map_err(|_| SampError::DecryptionFailed);
    shared_secret.zeroize();
    sym_key.zeroize();
    result
}

/// Decrypt as the sender (1:1 self-decryption via sealed_to + deterministic ephemeral).
pub fn decrypt_as_sender(
    content: &[u8],
    sender_seed: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, SampError> {
    if content.len() < ENCRYPTED_OVERHEAD {
        return Err(SampError::InsufficientData);
    }
    let sealed_to: [u8; 32] = content[32..64].try_into().unwrap();
    let mut recipient_bytes = seal_recipient(&sealed_to, sender_seed, nonce);
    let recipient_pubkey = CompressedRistretto(recipient_bytes);
    let mut eph_bytes = derive_ephemeral(sender_seed, &recipient_bytes, nonce);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let mut shared_secret = ecdh_shared_secret(&eph_scalar, &recipient_pubkey)?;
    let mut sym_key = derive_symmetric_key(&shared_secret, nonce);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let result = cipher
        .decrypt(Nonce::from_slice(nonce), &content[64..])
        .map_err(|_| SampError::DecryptionFailed);
    recipient_bytes.zeroize();
    eph_bytes.zeroize();
    shared_secret.zeroize();
    sym_key.zeroize();
    result
}

// ---------------------------------------------------------------------------
// Multi-Recipient Encryption (Section 5.7) -- used by 0x15 (group)
// ---------------------------------------------------------------------------

/// Derive the shared group ephemeral scalar from sender seed + nonce.
pub fn derive_group_ephemeral(sender_seed: &[u8; 32], nonce: &[u8; 12]) -> Scalar {
    let hk = Hkdf::<Sha256>::new(None, sender_seed);
    let mut info = Vec::with_capacity(GROUP_EPH_INFO.len() + nonce.len());
    info.extend_from_slice(GROUP_EPH_INFO);
    info.extend_from_slice(nonce);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("valid HKDF");
    let scalar = Scalar::from_bytes_mod_order(okm);
    okm.zeroize();
    scalar
}

fn derive_key_wrap(shared_secret: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), shared_secret);
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

/// Build capsules for N members. Returns N * CAPSULE_SIZE bytes.
/// Each capsule: view_tag(1) + wrapped_key(32).
pub fn build_capsules(
    content_key: &[u8; 32],
    member_pubkeys: &[[u8; 32]],
    eph_scalar: &Scalar,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(member_pubkeys.len() * CAPSULE_SIZE);
    for pubkey in member_pubkeys {
        let point = CompressedRistretto(*pubkey);
        let mut shared = match ecdh_shared_secret(eph_scalar, &point) {
            Ok(s) => s,
            Err(_) => {
                // Invalid pubkey -- write zero capsule (recipient won't match)
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

/// Scan capsules for a matching view tag. Returns the unwrapped content key on match.
/// `data` is the bytes after eph_pubkey: capsules(33*N) + ciphertext.
pub fn scan_capsules(
    data: &[u8],
    eph_pubkey: &CompressedRistretto,
    my_scalar: &Scalar,
    nonce: &[u8; 12],
) -> Option<(usize, [u8; 32])> {
    let mut shared = ecdh_shared_secret(my_scalar, eph_pubkey).ok()?;
    let my_tag = derive_view_tag(&shared);
    let mut kek = derive_key_wrap(&shared, nonce);

    // Scan 33-byte capsule slots
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

/// Encrypt plaintext for multiple recipients. Returns (eph_pubkey_bytes, capsules, ciphertext_with_tag).
pub fn encrypt_for_group(
    plaintext: &[u8],
    member_pubkeys: &[[u8; 32]],
    nonce: &[u8; 12],
    sender_seed: &[u8; 32],
) -> Result<GroupEncrypted, SampError> {
    let eph_scalar = derive_group_ephemeral(sender_seed, nonce);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();

    // Random per-message content key
    let mut content_key = [0u8; 32];
    getrandom::fill(&mut content_key).map_err(|_| SampError::DecryptionFailed)?;

    let capsules = build_capsules(&content_key, member_pubkeys, &eph_scalar, nonce);

    let cipher = ChaCha20Poly1305::new((&content_key).into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| SampError::DecryptionFailed)?;

    content_key.zeroize();
    Ok((eph_pubkey.to_bytes(), capsules, ciphertext))
}

/// Decrypt a group message. `content` is everything after the nonce in the remark:
/// eph_pubkey(32) + capsules(33*N) + ciphertext.
/// If `known_member_count` is provided, uses it for the capsule/ciphertext boundary.
/// Otherwise, uses trial AEAD decryption at successive 33-byte boundaries.
pub fn decrypt_from_group(
    content: &[u8],
    my_scalar: &Scalar,
    nonce: &[u8; 12],
    known_member_count: Option<usize>,
) -> Result<Vec<u8>, SampError> {
    if content.len() < 32 {
        return Err(SampError::InsufficientData);
    }
    let eph_pubkey = CompressedRistretto(content[..32].try_into().unwrap());
    let after_eph = &content[32..];

    // Find our capsule and get the content key
    let (capsule_idx, mut content_key) = scan_capsules(after_eph, &eph_pubkey, my_scalar, nonce)
        .ok_or(SampError::DecryptionFailed)?;

    let cipher = ChaCha20Poly1305::new((&content_key).into());

    if let Some(n) = known_member_count {
        // Known boundary
        let ct_start = n * CAPSULE_SIZE;
        if ct_start > after_eph.len() {
            content_key.zeroize();
            return Err(SampError::InsufficientData);
        }
        let result = cipher
            .decrypt(Nonce::from_slice(nonce), &after_eph[ct_start..])
            .map_err(|_| SampError::DecryptionFailed);
        content_key.zeroize();
        return result;
    }

    // Trial AEAD: try boundaries from capsule_idx+1 upward
    let min_n = capsule_idx + 1;
    let max_n = (after_eph.len().saturating_sub(16)) / CAPSULE_SIZE; // need at least 16 bytes for auth_tag
    for n in min_n..=max_n {
        let ct_start = n * CAPSULE_SIZE;
        if ct_start >= after_eph.len() {
            break;
        }
        if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(nonce), &after_eph[ct_start..]) {
            content_key.zeroize();
            return Ok(plaintext);
        }
    }
    content_key.zeroize();
    Err(SampError::DecryptionFailed)
}
