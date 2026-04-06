use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use sha2::Sha256;

const MESSAGE_KEY_INFO: &[u8] = b"samp-message-v1";
const VIEW_TAG_INFO: &[u8] = b"samp-view-tag-v1";
const SEAL_INFO: &[u8] = b"samp-seal-v1";
const GROUP_EPH_INFO: &[u8] = b"samp-group-eph";
const KEY_WRAP_INFO: &[u8] = b"samp-key-wrap-v1";
const CAPSULE_SIZE: usize = 33;

/// Encrypted content overhead: ephemeral(32) + sealed_to(32) + auth_tag(16) = 80 bytes.
const ENCRYPTED_OVERHEAD: usize = 80;

fn err(msg: &str) -> PyErr {
    PyValueError::new_err(msg.to_string())
}

fn seed_to_keypair(seed: &[u8]) -> PyResult<schnorrkel::Keypair> {
    if seed.len() != 32 {
        return Err(err("seed must be 32 bytes"));
    }
    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let msk = MiniSecretKey::from_bytes(&seed_arr).map_err(|e| err(&e.to_string()))?;
    Ok(msk.expand_to_keypair(ExpansionMode::Ed25519))
}

#[pyfunction]
fn public_from_seed(seed: &[u8]) -> PyResult<Vec<u8>> {
    let kp = seed_to_keypair(seed)?;
    Ok(kp.public.to_bytes().to_vec())
}

#[pyfunction]
fn sr25519_signing_scalar(seed: &[u8]) -> PyResult<Vec<u8>> {
    if seed.len() != 32 {
        return Err(err("seed must be 32 bytes"));
    }
    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let msk = MiniSecretKey::from_bytes(&seed_arr).map_err(|e| err(&e.to_string()))?;
    let secret = msk.expand(ExpansionMode::Ed25519);
    Ok(secret.to_bytes()[..32].to_vec())
}

#[pyfunction]
fn ecdh(scalar: &[u8], point: &[u8]) -> PyResult<Vec<u8>> {
    if scalar.len() != 32 || point.len() != 32 {
        return Err(err("scalar and point must be 32 bytes"));
    }
    let s = Scalar::from_bytes_mod_order(scalar.try_into().unwrap());
    let p = CompressedRistretto(point.try_into().unwrap())
        .decompress()
        .ok_or_else(|| err("invalid ristretto255 point"))?;
    Ok((s * p).compress().to_bytes().to_vec())
}

#[pyfunction]
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> PyResult<Vec<u8>> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out).map_err(|e| err(&e.to_string()))?;
    Ok(out)
}

#[pyfunction]
fn chacha20poly1305_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(err("key must be 32 bytes, nonce must be 12 bytes"));
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).map_err(|e| err(&e.to_string()))
}

#[pyfunction]
fn chacha20poly1305_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(err("key must be 32 bytes, nonce must be 12 bytes"));
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| err("decryption failed"))
}

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

fn derive_symmetric_key(shared_secret: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(MESSAGE_KEY_INFO, &mut key).expect("valid HKDF");
    key
}

/// Compute the 1-byte view tag for recipient scanning.
#[pyfunction]
fn compute_view_tag(sender_seed: &[u8], recipient_pubkey: &[u8], nonce: &[u8]) -> PyResult<u8> {
    if sender_seed.len() != 32 || recipient_pubkey.len() != 32 || nonce.len() != 12 {
        return Err(err("sender_seed and recipient_pubkey must be 32 bytes, nonce must be 12 bytes"));
    }
    let seed: [u8; 32] = sender_seed.try_into().unwrap();
    let recip: [u8; 32] = recipient_pubkey.try_into().unwrap();
    let n: [u8; 12] = nonce.try_into().unwrap();

    let eph_bytes = derive_ephemeral(&seed, &recip, &n);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let recip_point = CompressedRistretto(recip)
        .decompress()
        .ok_or_else(|| err("invalid recipient pubkey"))?;
    let shared = (eph_scalar * recip_point).compress().to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut tag = [0u8; 1];
    hk.expand(VIEW_TAG_INFO, &mut tag).expect("valid HKDF");
    Ok(tag[0])
}

/// Encrypt plaintext for a recipient using the sender's seed.
/// Returns: ephemeral(32) || sealed_to(32) || ciphertext || auth_tag(16).
#[pyfunction]
fn encrypt_content(plaintext: &[u8], recipient_pubkey: &[u8], nonce: &[u8], sender_seed: &[u8]) -> PyResult<Vec<u8>> {
    if recipient_pubkey.len() != 32 || nonce.len() != 12 || sender_seed.len() != 32 {
        return Err(err("recipient_pubkey and sender_seed must be 32 bytes, nonce must be 12 bytes"));
    }
    let recip: [u8; 32] = recipient_pubkey.try_into().unwrap();
    let n: [u8; 12] = nonce.try_into().unwrap();
    let seed: [u8; 32] = sender_seed.try_into().unwrap();

    let recipient_point = CompressedRistretto(recip)
        .decompress()
        .ok_or_else(|| err("invalid recipient pubkey"))?;

    // Deterministic ephemeral from sender seed
    let eph_bytes = derive_ephemeral(&seed, &recip, &n);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();

    // ECDH shared secret
    let shared = (eph_scalar * recipient_point).compress().to_bytes();

    // Sealed recipient (for sender self-decryption)
    let seal_key = derive_seal_key(&seed, &n);
    let mut sealed_to = [0u8; 32];
    for i in 0..32 {
        sealed_to[i] = recip[i] ^ seal_key[i];
    }

    // Symmetric encryption
    let sym_key = derive_symmetric_key(&shared, &n);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let ct = cipher.encrypt(Nonce::from_slice(&n), plaintext).map_err(|e| err(&e.to_string()))?;

    let mut out = Vec::with_capacity(ENCRYPTED_OVERHEAD + plaintext.len());
    out.extend_from_slice(&eph_pubkey.to_bytes());
    out.extend_from_slice(&sealed_to);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt as the recipient: shared_secret = signing_scalar * ephemeral.
/// Content: ephemeral(32) || sealed_to(32) || ciphertext || auth_tag(16).
#[pyfunction]
fn decrypt_content(content: &[u8], signing_scalar: &[u8], nonce: &[u8]) -> PyResult<Vec<u8>> {
    if signing_scalar.len() != 32 || nonce.len() != 12 {
        return Err(err("signing_scalar must be 32 bytes, nonce must be 12 bytes"));
    }
    if content.len() < ENCRYPTED_OVERHEAD {
        return Err(err("content too short"));
    }
    let eph_pubkey = CompressedRistretto(content[..32].try_into().unwrap())
        .decompress()
        .ok_or_else(|| err("invalid ephemeral pubkey"))?;
    let scalar = Scalar::from_bytes_mod_order(signing_scalar.try_into().unwrap());
    let n: [u8; 12] = nonce.try_into().unwrap();

    let shared = (scalar * eph_pubkey).compress().to_bytes();
    // Skip sealed_to (bytes 32..64), decrypt from byte 64
    let sym_key = derive_symmetric_key(&shared, &n);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    cipher.decrypt(Nonce::from_slice(&n), &content[64..])
        .map_err(|_| err("decryption failed"))
}

/// Decrypt as the sender: unseal recipient, re-derive ephemeral, compute shared secret.
/// Content: ephemeral(32) || sealed_to(32) || ciphertext || auth_tag(16).
#[pyfunction]
fn decrypt_as_sender(content: &[u8], sender_seed: &[u8], nonce: &[u8]) -> PyResult<Vec<u8>> {
    if sender_seed.len() != 32 || nonce.len() != 12 {
        return Err(err("sender_seed must be 32 bytes, nonce must be 12 bytes"));
    }
    if content.len() < ENCRYPTED_OVERHEAD {
        return Err(err("content too short"));
    }
    let seed: [u8; 32] = sender_seed.try_into().unwrap();
    let n: [u8; 12] = nonce.try_into().unwrap();

    // Unseal recipient pubkey
    let sealed_to: [u8; 32] = content[32..64].try_into().unwrap();
    let seal_key = derive_seal_key(&seed, &n);
    let mut recipient = [0u8; 32];
    for i in 0..32 {
        recipient[i] = sealed_to[i] ^ seal_key[i];
    }
    let recipient_point = CompressedRistretto(recipient)
        .decompress()
        .ok_or_else(|| err("invalid unsealed recipient pubkey"))?;

    // Re-derive ephemeral and compute shared secret
    let eph_bytes = derive_ephemeral(&seed, &recipient, &n);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let shared = (eph_scalar * recipient_point).compress().to_bytes();

    let sym_key = derive_symmetric_key(&shared, &n);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    cipher.decrypt(Nonce::from_slice(&n), &content[64..])
        .map_err(|_| err("decryption failed"))
}

/// Recipient-side view tag check (Section 5.3).
#[pyfunction]
fn check_view_tag(signing_scalar: &[u8], encrypted_content: &[u8]) -> PyResult<u8> {
    if signing_scalar.len() != 32 {
        return Err(err("signing_scalar must be 32 bytes"));
    }
    if encrypted_content.len() < ENCRYPTED_OVERHEAD {
        return Err(err("content too short"));
    }
    let eph_pubkey = CompressedRistretto(encrypted_content[..32].try_into().unwrap())
        .decompress()
        .ok_or_else(|| err("invalid ephemeral pubkey"))?;
    let scalar = Scalar::from_bytes_mod_order(signing_scalar.try_into().unwrap());
    let shared = (scalar * eph_pubkey).compress().to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut tag = [0u8; 1];
    hk.expand(VIEW_TAG_INFO, &mut tag).expect("valid HKDF");
    Ok(tag[0])
}

/// Recover recipient pubkey from sealed_to (Section 5.5 step 3).
#[pyfunction]
fn unseal_recipient(encrypted_content: &[u8], sender_seed: &[u8], nonce: &[u8]) -> PyResult<Vec<u8>> {
    if sender_seed.len() != 32 || nonce.len() != 12 {
        return Err(err("sender_seed must be 32 bytes, nonce must be 12 bytes"));
    }
    if encrypted_content.len() < ENCRYPTED_OVERHEAD {
        return Err(err("content too short"));
    }
    let seed: [u8; 32] = sender_seed.try_into().unwrap();
    let n: [u8; 12] = nonce.try_into().unwrap();
    let sealed_to: [u8; 32] = encrypted_content[32..64].try_into().unwrap();
    let seal_key = derive_seal_key(&seed, &n);
    let mut recipient = [0u8; 32];
    for i in 0..32 {
        recipient[i] = sealed_to[i] ^ seal_key[i];
    }
    Ok(recipient.to_vec())
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

fn derive_view_tag(shared_secret: &[u8; 32]) -> u8 {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut tag = [0u8; 1];
    hk.expand(VIEW_TAG_INFO, &mut tag).expect("valid HKDF");
    tag[0]
}

fn ecdh_shared(scalar: &Scalar, point: &CompressedRistretto) -> PyResult<[u8; 32]> {
    let p = point.decompress().ok_or_else(|| err("invalid ristretto255 point"))?;
    Ok((scalar * p).compress().to_bytes())
}

#[pyfunction]
fn derive_group_ephemeral(sender_seed: &[u8], nonce: &[u8]) -> PyResult<Vec<u8>> {
    let seed: [u8; 32] = sender_seed.try_into().map_err(|_| err("seed must be 32 bytes"))?;
    let n: [u8; 12] = nonce.try_into().map_err(|_| err("nonce must be 12 bytes"))?;
    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut info = Vec::with_capacity(GROUP_EPH_INFO.len() + n.len());
    info.extend_from_slice(GROUP_EPH_INFO);
    info.extend_from_slice(&n);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("valid HKDF");
    let scalar = Scalar::from_bytes_mod_order(okm);
    Ok(scalar.to_bytes().to_vec())
}

#[pyfunction]
fn build_capsules(content_key: &[u8], member_pubkeys: Vec<Vec<u8>>, eph_scalar: &[u8], nonce: &[u8]) -> PyResult<Vec<u8>> {
    let ck: [u8; 32] = content_key.try_into().map_err(|_| err("content_key must be 32 bytes"))?;
    let es = Scalar::from_bytes_mod_order(eph_scalar.try_into().map_err(|_| err("eph_scalar must be 32 bytes"))?);
    let n: [u8; 12] = nonce.try_into().map_err(|_| err("nonce must be 12 bytes"))?;
    let mut out = Vec::with_capacity(member_pubkeys.len() * CAPSULE_SIZE);
    for pk_vec in &member_pubkeys {
        let pk: [u8; 32] = pk_vec.as_slice().try_into().map_err(|_| err("each pubkey must be 32 bytes"))?;
        let point = CompressedRistretto(pk);
        let shared = match ecdh_shared(&es, &point) {
            Ok(s) => s,
            Err(_) => {
                out.extend_from_slice(&[0u8; CAPSULE_SIZE]);
                continue;
            }
        };
        let tag = derive_view_tag(&shared);
        let kek = derive_key_wrap(&shared, &n);
        let wrapped = xor32(&ck, &kek);
        out.push(tag);
        out.extend_from_slice(&wrapped);
    }
    Ok(out)
}

#[pyfunction]
fn scan_capsules(data: &[u8], eph_pubkey: &[u8], my_scalar: &[u8], nonce: &[u8]) -> PyResult<Option<(usize, Vec<u8>)>> {
    let ep: [u8; 32] = eph_pubkey.try_into().map_err(|_| err("eph_pubkey must be 32 bytes"))?;
    let ms = Scalar::from_bytes_mod_order(my_scalar.try_into().map_err(|_| err("my_scalar must be 32 bytes"))?);
    let n: [u8; 12] = nonce.try_into().map_err(|_| err("nonce must be 12 bytes"))?;
    let point = CompressedRistretto(ep);
    let shared = match ecdh_shared(&ms, &point) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let my_tag = derive_view_tag(&shared);
    let kek = derive_key_wrap(&shared, &n);
    let mut offset = 0;
    let mut idx = 0;
    while offset + CAPSULE_SIZE <= data.len() {
        if data[offset] == my_tag {
            let mut wrapped = [0u8; 32];
            wrapped.copy_from_slice(&data[offset + 1..offset + 33]);
            let content_key = xor32(&wrapped, &kek);
            return Ok(Some((idx, content_key.to_vec())));
        }
        offset += CAPSULE_SIZE;
        idx += 1;
    }
    Ok(None)
}

#[pyfunction]
fn encrypt_for_group(plaintext: &[u8], member_pubkeys: Vec<Vec<u8>>, nonce: &[u8], sender_seed: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let seed: [u8; 32] = sender_seed.try_into().map_err(|_| err("sender_seed must be 32 bytes"))?;
    let n: [u8; 12] = nonce.try_into().map_err(|_| err("nonce must be 12 bytes"))?;

    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut info = Vec::with_capacity(GROUP_EPH_INFO.len() + n.len());
    info.extend_from_slice(GROUP_EPH_INFO);
    info.extend_from_slice(&n);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("valid HKDF");
    let eph_scalar = Scalar::from_bytes_mod_order(okm);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();

    let mut content_key = [0u8; 32];
    getrandom::getrandom(&mut content_key).map_err(|_| err("RNG failed"))?;

    let mut capsules = Vec::with_capacity(member_pubkeys.len() * CAPSULE_SIZE);
    for pk_vec in &member_pubkeys {
        let pk: [u8; 32] = pk_vec.as_slice().try_into().map_err(|_| err("each pubkey must be 32 bytes"))?;
        let point = CompressedRistretto(pk);
        let shared = match ecdh_shared(&eph_scalar, &point) {
            Ok(s) => s,
            Err(_) => {
                capsules.extend_from_slice(&[0u8; CAPSULE_SIZE]);
                continue;
            }
        };
        let tag = derive_view_tag(&shared);
        let kek = derive_key_wrap(&shared, &n);
        let wrapped = xor32(&content_key, &kek);
        capsules.push(tag);
        capsules.extend_from_slice(&wrapped);
    }

    let cipher = ChaCha20Poly1305::new((&content_key).into());
    let ciphertext = cipher.encrypt(Nonce::from_slice(&n), plaintext).map_err(|e| err(&e.to_string()))?;

    Ok((eph_pubkey.to_bytes().to_vec(), capsules, ciphertext))
}

#[pyfunction]
fn decrypt_from_group(content: &[u8], my_scalar: &[u8], nonce: &[u8], known_n: Option<usize>) -> PyResult<Vec<u8>> {
    let ms = Scalar::from_bytes_mod_order(my_scalar.try_into().map_err(|_| err("my_scalar must be 32 bytes"))?);
    let n: [u8; 12] = nonce.try_into().map_err(|_| err("nonce must be 12 bytes"))?;
    if content.len() < 32 {
        return Err(err("content too short"));
    }
    let eph_pubkey = CompressedRistretto(content[..32].try_into().unwrap());
    let after_eph = &content[32..];

    let shared = ecdh_shared(&ms, &eph_pubkey).map_err(|_| err("decryption failed"))?;
    let my_tag = derive_view_tag(&shared);
    let kek = derive_key_wrap(&shared, &n);

    let mut offset = 0;
    let mut capsule_idx = 0;
    let mut content_key: Option<[u8; 32]> = None;
    while offset + CAPSULE_SIZE <= after_eph.len() {
        if after_eph[offset] == my_tag {
            let mut wrapped = [0u8; 32];
            wrapped.copy_from_slice(&after_eph[offset + 1..offset + 33]);
            content_key = Some(xor32(&wrapped, &kek));
            break;
        }
        offset += CAPSULE_SIZE;
        capsule_idx += 1;
    }
    let ck = content_key.ok_or_else(|| err("decryption failed"))?;
    let cipher = ChaCha20Poly1305::new((&ck).into());

    if let Some(member_count) = known_n {
        let ct_start = member_count * CAPSULE_SIZE;
        if ct_start > after_eph.len() {
            return Err(err("content too short"));
        }
        return cipher.decrypt(Nonce::from_slice(&n), &after_eph[ct_start..])
            .map_err(|_| err("decryption failed"));
    }

    let min_n = capsule_idx + 1;
    let max_n = after_eph.len().saturating_sub(16) / CAPSULE_SIZE;
    for trial_n in min_n..=max_n {
        let ct_start = trial_n * CAPSULE_SIZE;
        if ct_start >= after_eph.len() { break; }
        if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&n), &after_eph[ct_start..]) {
            return Ok(plaintext);
        }
    }
    Err(err("decryption failed"))
}

#[pymodule]
fn samp_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(public_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(sr25519_signing_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(ecdh, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(chacha20poly1305_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(chacha20poly1305_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(compute_view_tag, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_content, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_content, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_as_sender, m)?)?;
    m.add_function(wrap_pyfunction!(check_view_tag, m)?)?;
    m.add_function(wrap_pyfunction!(unseal_recipient, m)?)?;
    m.add_function(wrap_pyfunction!(derive_group_ephemeral, m)?)?;
    m.add_function(wrap_pyfunction!(build_capsules, m)?)?;
    m.add_function(wrap_pyfunction!(scan_capsules, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_for_group, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_from_group, m)?)?;
    Ok(())
}
