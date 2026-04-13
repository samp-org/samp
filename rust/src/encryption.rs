use crate::error::SampError;
use crate::secret::{ContentKey, Seed, ViewScalar};
use crate::types::{Capsules, Ciphertext, EphPubkey, Nonce, Plaintext, Pubkey, ViewTag};
use crate::wire::CAPSULE_SIZE;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use schnorrkel::signing_context;
use sha2::Sha256;
use zeroize::Zeroize;

pub type GroupEncrypted = (EphPubkey, Capsules, Ciphertext);

const MESSAGE_KEY_INFO: &[u8] = b"samp-message";
const VIEW_TAG_INFO: &[u8] = b"samp-view-tag";
const SEAL_INFO: &[u8] = b"samp-seal";
const GROUP_EPH_INFO: &[u8] = b"samp-group-eph";
const KEY_WRAP_INFO: &[u8] = b"samp-key-wrap";

pub const ENCRYPTED_OVERHEAD: usize = 80;

// WHY: the single crypto boundary that turns a 32-byte ViewScalar back into a
// ristretto255 scalar. Every decrypt path funnels through here.
pub(crate) fn view_scalar_to_ristretto(vs: &ViewScalar) -> Scalar {
    Scalar::from_bytes_mod_order(*vs.expose_secret())
}

pub fn sr25519_sign(seed: &Seed, message: &[u8]) -> crate::types::Signature {
    let msk = MiniSecretKey::from_bytes(seed.expose_secret()).expect("valid 32-byte seed");
    let kp = msk.expand_to_keypair(ExpansionMode::Ed25519);
    let sig = kp.sign(signing_context(b"substrate").bytes(message));
    crate::types::Signature::from_bytes(sig.to_bytes())
}

pub fn sr25519_signing_scalar(seed: &Seed) -> ViewScalar {
    let msk = MiniSecretKey::from_bytes(seed.expose_secret()).expect("valid 32-byte seed");
    let secret = msk.expand(ExpansionMode::Ed25519);
    let mut scalar_bytes: [u8; 32] = secret.to_bytes()[..32].try_into().unwrap();
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    scalar_bytes.zeroize();
    ViewScalar::from_bytes(scalar.to_bytes())
}

pub fn public_from_seed(seed: &Seed) -> Pubkey {
    let vs = sr25519_signing_scalar(seed);
    let scalar = view_scalar_to_ristretto(&vs);
    Pubkey::from_bytes((scalar * RISTRETTO_BASEPOINT_POINT).compress().to_bytes())
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
) -> Result<ViewTag, SampError> {
    let recipient_point = recipient_pubkey.to_compressed_ristretto();
    let eph_bytes = derive_ephemeral(sender_seed, recipient_pubkey.as_bytes(), nonce);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let shared = ecdh_shared_secret(&eph_scalar, &recipient_point)?;
    Ok(ViewTag::new(derive_view_tag(&shared)))
}

fn ensure_ciphertext_size(ciphertext: &Ciphertext) -> Result<(), SampError> {
    if ciphertext.len() < ENCRYPTED_OVERHEAD {
        return Err(SampError::InsufficientData);
    }
    Ok(())
}

pub fn check_view_tag(
    ciphertext: &Ciphertext,
    signing_scalar: &ViewScalar,
) -> Result<ViewTag, SampError> {
    ensure_ciphertext_size(ciphertext)?;
    let eph_pubkey = CompressedRistretto(ciphertext.as_bytes()[..32].try_into().unwrap());
    let scalar = view_scalar_to_ristretto(signing_scalar);
    let shared = ecdh_shared_secret(&scalar, &eph_pubkey)?;
    Ok(ViewTag::new(derive_view_tag(&shared)))
}

pub fn unseal_recipient(
    ciphertext: &Ciphertext,
    nonce: &Nonce,
    sender_seed: &Seed,
) -> Result<Pubkey, SampError> {
    ensure_ciphertext_size(ciphertext)?;
    let sealed_to: [u8; 32] = ciphertext.as_bytes()[32..64].try_into().unwrap();
    let key = derive_seal_key(sender_seed, nonce);
    let mut recipient = [0u8; 32];
    for i in 0..32 {
        recipient[i] = sealed_to[i] ^ key[i];
    }
    Ok(Pubkey::from_bytes(recipient))
}

pub fn encrypt(
    plaintext: &Plaintext,
    recipient_pubkey: &Pubkey,
    nonce: &Nonce,
    sender_seed: &Seed,
) -> Result<Ciphertext, SampError> {
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
                msg: plaintext.as_bytes(),
                aad: &sealed_to,
            },
        )
        .map_err(|_| SampError::DecryptionFailed)?;

    let mut content = Vec::with_capacity(ENCRYPTED_OVERHEAD + plaintext.as_bytes().len());
    content.extend_from_slice(&eph_pubkey.to_bytes());
    content.extend_from_slice(&sealed_to);
    content.extend_from_slice(&ciphertext_with_tag);

    eph_bytes.zeroize();
    shared_secret.zeroize();
    sealed_to.zeroize();
    sym_key.zeroize();
    Ok(Ciphertext::from_bytes(content))
}

pub fn decrypt(
    ciphertext: &Ciphertext,
    nonce: &Nonce,
    signing_scalar: &ViewScalar,
) -> Result<Plaintext, SampError> {
    ensure_ciphertext_size(ciphertext)?;
    let content = ciphertext.as_bytes();
    let eph_pubkey = CompressedRistretto(content[..32].try_into().unwrap());
    let sealed_to: [u8; 32] = content[32..64].try_into().unwrap();
    let scalar = view_scalar_to_ristretto(signing_scalar);
    let mut shared_secret = ecdh_shared_secret(&scalar, &eph_pubkey)?;
    let mut sym_key = derive_symmetric_key(&shared_secret, nonce);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let result = cipher
        .decrypt(
            ChaChaNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: &content[64..],
                aad: &sealed_to,
            },
        )
        .map(Plaintext::from_bytes)
        .map_err(|_| SampError::DecryptionFailed);
    shared_secret.zeroize();
    sym_key.zeroize();
    result
}

pub fn decrypt_as_sender(
    ciphertext: &Ciphertext,
    nonce: &Nonce,
    sender_seed: &Seed,
) -> Result<Plaintext, SampError> {
    ensure_ciphertext_size(ciphertext)?;
    let content = ciphertext.as_bytes();
    let sealed_to: [u8; 32] = content[32..64].try_into().unwrap();
    let mut recipient_bytes = seal_recipient(&sealed_to, sender_seed, nonce);
    let recipient_pubkey = CompressedRistretto(recipient_bytes);
    let mut eph_bytes = derive_ephemeral(sender_seed, &recipient_bytes, nonce);
    let eph_scalar = Scalar::from_bytes_mod_order(eph_bytes);
    let mut shared_secret = ecdh_shared_secret(&eph_scalar, &recipient_pubkey)?;
    let mut sym_key = derive_symmetric_key(&shared_secret, nonce);
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let result = cipher
        .decrypt(
            ChaChaNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: &content[64..],
                aad: &sealed_to,
            },
        )
        .map(Plaintext::from_bytes)
        .map_err(|_| SampError::DecryptionFailed);
    recipient_bytes.zeroize();
    eph_bytes.zeroize();
    shared_secret.zeroize();
    sym_key.zeroize();
    result
}

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
    content_key: &ContentKey,
    member_pubkeys: &[Pubkey],
    eph_scalar: &Scalar,
    nonce: &Nonce,
) -> Capsules {
    let ck = content_key.expose_secret();
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
        let wrapped = xor32(ck, &kek);
        out.push(tag);
        out.extend_from_slice(&wrapped);
        shared.zeroize();
        kek.zeroize();
    }
    Capsules::from_bytes(out).expect("len is multiple of CAPSULE_SIZE by construction")
}

pub(crate) fn scan_capsules(
    data: &[u8],
    eph_pubkey: &EphPubkey,
    my_scalar: &Scalar,
    nonce: &Nonce,
) -> Option<(usize, ContentKey)> {
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
            let content_key = ContentKey::from_bytes(xor32(&wrapped, &kek));
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
    plaintext: &Plaintext,
    member_pubkeys: &[Pubkey],
    nonce: &Nonce,
    sender_seed: &Seed,
) -> Result<GroupEncrypted, SampError> {
    let eph_scalar = derive_group_ephemeral(sender_seed, nonce);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();

    let mut ck_bytes = [0u8; 32];
    getrandom::fill(&mut ck_bytes).map_err(|_| SampError::DecryptionFailed)?;
    let content_key = ContentKey::from_bytes(ck_bytes);
    ck_bytes.zeroize();

    let capsules = build_capsules(&content_key, member_pubkeys, &eph_scalar, nonce);

    let cipher = ChaCha20Poly1305::new(content_key.expose_secret().into());
    let ciphertext = cipher
        .encrypt(
            ChaChaNonce::from_slice(nonce.as_bytes()),
            plaintext.as_bytes(),
        )
        .map_err(|_| SampError::DecryptionFailed)?;

    Ok((
        EphPubkey::from_bytes(eph_pubkey.to_bytes()),
        capsules,
        Ciphertext::from_bytes(ciphertext),
    ))
}

pub fn decrypt_from_group(
    content: &[u8],
    nonce: &Nonce,
    my_scalar: &ViewScalar,
    known_member_count: Option<usize>,
) -> Result<Plaintext, SampError> {
    if content.len() < 32 {
        return Err(SampError::InsufficientData);
    }
    let eph_pubkey = EphPubkey::from_bytes(content[..32].try_into().unwrap());
    let after_eph = &content[32..];

    let scalar = view_scalar_to_ristretto(my_scalar);
    let (capsule_idx, content_key) =
        scan_capsules(after_eph, &eph_pubkey, &scalar, nonce).ok_or(SampError::DecryptionFailed)?;

    let cipher = ChaCha20Poly1305::new(content_key.expose_secret().into());

    if let Some(n) = known_member_count {
        let ct_start = n * CAPSULE_SIZE;
        if ct_start > after_eph.len() {
            return Err(SampError::InsufficientData);
        }
        let result = cipher
            .decrypt(
                ChaChaNonce::from_slice(nonce.as_bytes()),
                &after_eph[ct_start..],
            )
            .map(Plaintext::from_bytes)
            .map_err(|_| SampError::DecryptionFailed);
        return result;
    }

    let min_n = capsule_idx + 1;
    let max_n = (after_eph.len().saturating_sub(16)) / CAPSULE_SIZE;
    for n in min_n..=max_n {
        let ct_start = n * CAPSULE_SIZE;
        if let Ok(plaintext) = cipher.decrypt(
            ChaChaNonce::from_slice(nonce.as_bytes()),
            &after_eph[ct_start..],
        ) {
            return Ok(Plaintext::from_bytes(plaintext));
        }
    }
    Err(SampError::DecryptionFailed)
}
