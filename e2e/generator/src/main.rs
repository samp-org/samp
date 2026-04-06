use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use serde::Serialize;
use sha2::Sha256;

use samp::encryption;
use samp::wire::*;

fn h(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[derive(Serialize)]
struct KeypairVec {
    seed: String,
    sr25519_public: String,
    signing_scalar: String,
}

#[derive(Serialize)]
struct PublicMsgVec {
    body: String,
    remark: String,
}

#[derive(Serialize)]
struct EncryptedMsgVec {
    nonce: String,
    plaintext: String,
    ephemeral_bytes: String,
    ephemeral_pubkey: String,
    shared_secret: String,
    view_tag: u8,
    seal_key: String,
    sealed_to: String,
    symmetric_key: String,
    ciphertext_with_tag: String,
    encrypted_content: String,
    remark: String,
}

#[derive(Serialize)]
struct ThreadMsgVec {
    nonce: String,
    thread_ref: [u32; 2],
    reply_to: [u32; 2],
    continues: [u32; 2],
    body: String,
    thread_plaintext: String,
    encrypted_content: String,
    remark: String,
}

#[derive(Serialize)]
struct SenderDecryptVec {
    seal_key: String,
    unsealed_recipient: String,
    re_derived_ephemeral_bytes: String,
    re_derived_shared_secret: String,
    plaintext: String,
}

#[derive(Serialize)]
struct ChannelMsgVec {
    body: String,
    channel_ref: [u32; 2],
    reply_to: [u32; 2],
    continues: [u32; 2],
    remark: String,
}

#[derive(Serialize)]
struct ChannelCreateVec {
    name: String,
    description: String,
    remark: String,
}

#[derive(Serialize)]
struct GroupMsgVec {
    nonce: String,
    members: Vec<String>,
    body: String,
    member_list_encoded: String,
    root_plaintext: String,
    content_key: String,
    eph_pubkey: String,
    capsules: String,
    ciphertext: String,
    remark: String,
}

#[derive(Serialize)]
struct EdgeCases {
    empty_body_public: String,
    min_encrypted: String,
    empty_desc_channel_create: String,
}

#[derive(Serialize)]
struct NegativeCases {
    non_samp_version: String,
    reserved_type: String,
    truncated_encrypted: String,
}

#[derive(Serialize)]
struct TestVectors {
    alice: KeypairVec,
    bob: KeypairVec,
    charlie: KeypairVec,
    public_message: PublicMsgVec,
    encrypted_message: EncryptedMsgVec,
    thread_message: ThreadMsgVec,
    sender_self_decryption: SenderDecryptVec,
    channel_message: ChannelMsgVec,
    channel_create: ChannelCreateVec,
    group_message: GroupMsgVec,
    edge_cases: EdgeCases,
    negative_cases: NegativeCases,
}

fn make_keypair_vec(seed: &[u8; 32]) -> KeypairVec {
    let msk = MiniSecretKey::from_bytes(seed).unwrap();
    let kp = msk.expand_to_keypair(ExpansionMode::Ed25519);
    let scalar = encryption::sr25519_signing_scalar(seed);
    KeypairVec {
        seed: h(seed),
        sr25519_public: h(&kp.public.to_bytes()),
        signing_scalar: h(&scalar.to_bytes()),
    }
}

fn main() {
    let alice_seed: [u8; 32] =
        hex::decode("e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a")
            .unwrap().try_into().unwrap();
    let bob_seed: [u8; 32] =
        hex::decode("398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89")
            .unwrap().try_into().unwrap();
    let charlie_seed: [u8; 32] = [0xCC; 32];
    let nonce: [u8; 12] =
        hex::decode("a1b2c3d4e5f6a7b8c9d0e1f2")
            .unwrap().try_into().unwrap();

    let alice_msk = MiniSecretKey::from_bytes(&alice_seed).unwrap();
    let alice_kp = alice_msk.expand_to_keypair(ExpansionMode::Ed25519);
    let bob_msk = MiniSecretKey::from_bytes(&bob_seed).unwrap();
    let bob_kp = bob_msk.expand_to_keypair(ExpansionMode::Ed25519);
    let bob_pub = bob_kp.public.to_bytes();
    let bob_pubkey = CompressedRistretto(bob_pub);
    let bob_scalar = encryption::sr25519_signing_scalar(&bob_seed);

    let charlie_pub = encryption::public_from_seed(&charlie_seed);
    let charlie_scalar = encryption::sr25519_signing_scalar(&charlie_seed);

    // === Public message ===
    let body = b"Hello";
    let public_remark = encode_public(&bob_pub, body);

    // === Encrypted message with full intermediates ===
    let plaintext = b"Hello Bob";

    // Step 1: Derive ephemeral
    let eph_hk = Hkdf::<Sha256>::new(None, &alice_seed);
    let mut eph_info = [0u8; 44];
    eph_info[..32].copy_from_slice(&bob_pub);
    eph_info[32..].copy_from_slice(&nonce);
    let mut ephemeral_bytes = [0u8; 32];
    eph_hk.expand(&eph_info, &mut ephemeral_bytes).unwrap();
    let eph_scalar = Scalar::from_bytes_mod_order(ephemeral_bytes);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();

    // Step 2: ECDH shared secret
    let bob_point = bob_pubkey.decompress().unwrap();
    let shared_secret = (eph_scalar * bob_point).compress().to_bytes();

    // Step 3: View tag
    let vt_hk = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut vt_buf = [0u8; 1];
    vt_hk.expand(b"samp-view-tag-v1", &mut vt_buf).unwrap();
    let view_tag = vt_buf[0];

    // Step 4: Seal key and sealed_to
    let seal_hk = Hkdf::<Sha256>::new(Some(&nonce), &alice_seed);
    let mut seal_key = [0u8; 32];
    seal_hk.expand(b"samp-seal-v1", &mut seal_key).unwrap();
    let mut sealed_to = [0u8; 32];
    for i in 0..32 {
        sealed_to[i] = bob_pub[i] ^ seal_key[i];
    }

    // Step 5: Symmetric key
    let sym_hk = Hkdf::<Sha256>::new(Some(&nonce), &shared_secret);
    let mut symmetric_key = [0u8; 32];
    sym_hk.expand(b"samp-message-v1", &mut symmetric_key).unwrap();

    // Step 6: Full encrypt (using the library to get the final bytes)
    let encrypted_content = encryption::encrypt(plaintext, &bob_pubkey, &nonce, &alice_seed).unwrap();
    let ciphertext_with_tag = &encrypted_content[64..]; // after eph_pubkey(32) + sealed_to(32)

    // Verify intermediates match library output
    assert_eq!(&encrypted_content[..32], eph_pubkey.to_bytes());
    assert_eq!(&encrypted_content[32..64], sealed_to);

    // Verify decryption works
    let decrypted = encryption::decrypt(&encrypted_content, &bob_scalar, &nonce).unwrap();
    assert_eq!(&decrypted, plaintext);

    let enc_remark = encode_encrypted(CONTENT_TYPE_ENCRYPTED, view_tag, &nonce, &encrypted_content);

    // === Thread message ===
    let thread_ref = BlockRef { block: 100, index: 0 };
    let reply_to_ref = BlockRef { block: 101, index: 1 };
    let continues_ref = BlockRef { block: 100, index: 0 };
    let thread_body = b"Re: subnet 7";
    let thread_plaintext = encode_thread_content(thread_ref, reply_to_ref, continues_ref, thread_body);
    let thread_nonce: [u8; 12] = hex::decode("b1c2d3e4f5a6b7c8d9e0f1a2").unwrap().try_into().unwrap();

    let thread_encrypted = encryption::encrypt(&thread_plaintext, &bob_pubkey, &thread_nonce, &alice_seed).unwrap();
    let thread_view_tag = encryption::compute_view_tag(&alice_seed, &bob_pubkey, &thread_nonce).unwrap();
    let thread_remark = encode_encrypted(CONTENT_TYPE_THREAD, thread_view_tag, &thread_nonce, &thread_encrypted);

    // Verify thread decryption
    let thread_decrypted = encryption::decrypt(&thread_encrypted, &bob_scalar, &thread_nonce).unwrap();
    assert_eq!(thread_decrypted, thread_plaintext);

    // === Sender self-decryption intermediates ===
    // Use the encrypted_message content, show the sender decryption path
    let sd_seal_hk = Hkdf::<Sha256>::new(Some(&nonce), &alice_seed);
    let mut sd_seal_key = [0u8; 32];
    sd_seal_hk.expand(b"samp-seal-v1", &mut sd_seal_key).unwrap();
    let sd_sealed_to: [u8; 32] = encrypted_content[32..64].try_into().unwrap();
    let mut sd_recipient = [0u8; 32];
    for i in 0..32 {
        sd_recipient[i] = sd_sealed_to[i] ^ sd_seal_key[i];
    }
    assert_eq!(sd_recipient, bob_pub);

    let sd_eph_hk = Hkdf::<Sha256>::new(None, &alice_seed);
    let mut sd_eph_info = [0u8; 44];
    sd_eph_info[..32].copy_from_slice(&sd_recipient);
    sd_eph_info[32..].copy_from_slice(&nonce);
    let mut sd_eph_bytes = [0u8; 32];
    sd_eph_hk.expand(&sd_eph_info, &mut sd_eph_bytes).unwrap();
    let sd_eph_scalar = Scalar::from_bytes_mod_order(sd_eph_bytes);
    let sd_recip_point = CompressedRistretto(sd_recipient).decompress().unwrap();
    let sd_shared = (sd_eph_scalar * sd_recip_point).compress().to_bytes();

    let sd_decrypted = encryption::decrypt_as_sender(&encrypted_content, &alice_seed, &nonce).unwrap();
    assert_eq!(&sd_decrypted, plaintext);

    // === Channel message ===
    let ch_body = b"Did he use MEV shield?";
    let ch_remark = encode_channel_msg(
        BlockRef { block: 100, index: 2 },
        BlockRef { block: 99, index: 1 },
        BlockRef::ZERO,
        ch_body,
    );

    // === Channel creation ===
    let create_remark = encode_channel_create("general", "General discussion").unwrap();

    // === Group message (deterministic, manual encryption) ===
    let group_nonce: [u8; 12] = [0xCC; 12];
    let group_body = b"Hello group";
    let alice_pub = alice_kp.public.to_bytes();
    let group_members: Vec<[u8; 32]> = vec![alice_pub, bob_pub, charlie_pub];
    let member_list_encoded = encode_group_members(&group_members);

    // ROOT message plaintext: member_list || body
    let mut root_plaintext = member_list_encoded.clone();
    root_plaintext.extend_from_slice(group_body);

    // Thread content wrapping: thread=ZERO, reply_to=ZERO, continues=ZERO for root
    let group_inner = encode_thread_content(BlockRef::ZERO, BlockRef::ZERO, BlockRef::ZERO, &root_plaintext);

    // Deterministic group encryption
    let content_key: [u8; 32] = [0xDD; 32];
    let eph_scalar = encryption::derive_group_ephemeral(&alice_seed, &group_nonce);
    let group_eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();
    let group_capsules = encryption::build_capsules(&content_key, &group_members.iter().map(|p| *p).collect::<Vec<_>>(), &eph_scalar, &group_nonce);

    let group_cipher = ChaCha20Poly1305::new((&content_key).into());
    let group_ciphertext = group_cipher
        .encrypt(Nonce::from_slice(&group_nonce), group_inner.as_slice())
        .expect("group encryption");

    let group_remark = encode_group(&group_nonce, &group_eph_pubkey.to_bytes(), &group_capsules, &group_ciphertext);

    // Verify: Bob can decrypt
    let group_content = &group_remark[13..]; // skip type(1) + nonce(12)
    let bob_decrypted = encryption::decrypt_from_group(group_content, &bob_scalar, &group_nonce, Some(3)).unwrap();
    assert_eq!(bob_decrypted, group_inner);

    // Verify: Charlie can decrypt
    let charlie_decrypted = encryption::decrypt_from_group(group_content, &charlie_scalar, &group_nonce, Some(3)).unwrap();
    assert_eq!(charlie_decrypted, group_inner);

    // Verify: random seed CANNOT decrypt
    let random_seed: [u8; 32] = [0xEE; 32];
    let random_scalar = encryption::sr25519_signing_scalar(&random_seed);
    assert!(encryption::decrypt_from_group(group_content, &random_scalar, &group_nonce, Some(3)).is_err());

    // === Edge cases ===
    let empty_body_public = encode_public(&bob_pub, b"");
    let min_encrypted = encryption::encrypt(b"", &bob_pubkey, &nonce, &alice_seed).unwrap();
    let min_enc_remark = encode_encrypted(CONTENT_TYPE_ENCRYPTED, view_tag, &nonce, &min_encrypted);
    let empty_desc_create = encode_channel_create("test", "").unwrap();

    // === Negative cases (hex of invalid bytes) ===
    let non_samp_version = hex::encode([0x21u8, 0x00]);
    let reserved_type = hex::encode([0x16u8]);
    let truncated_encrypted = hex::encode([0x12u8, 0x00, 0x01, 0x02]); // only 4 bytes, need 14

    let vectors = TestVectors {
        alice: make_keypair_vec(&alice_seed),
        bob: make_keypair_vec(&bob_seed),
        charlie: make_keypair_vec(&charlie_seed),
        public_message: PublicMsgVec {
            body: h(body),
            remark: h(&public_remark),
        },
        encrypted_message: EncryptedMsgVec {
            nonce: h(&nonce),
            plaintext: h(plaintext),
            ephemeral_bytes: h(&ephemeral_bytes),
            ephemeral_pubkey: h(&eph_pubkey.to_bytes()),
            shared_secret: h(&shared_secret),
            view_tag,
            seal_key: h(&seal_key),
            sealed_to: h(&sealed_to),
            symmetric_key: h(&symmetric_key),
            ciphertext_with_tag: h(ciphertext_with_tag),
            encrypted_content: h(&encrypted_content),
            remark: h(&enc_remark),
        },
        thread_message: ThreadMsgVec {
            nonce: h(&thread_nonce),
            thread_ref: [100, 0],
            reply_to: [101, 1],
            continues: [100, 0],
            body: h(thread_body),
            thread_plaintext: h(&thread_plaintext),
            encrypted_content: h(&thread_encrypted),
            remark: h(&thread_remark),
        },
        sender_self_decryption: SenderDecryptVec {
            seal_key: h(&sd_seal_key),
            unsealed_recipient: h(&sd_recipient),
            re_derived_ephemeral_bytes: h(&sd_eph_bytes),
            re_derived_shared_secret: h(&sd_shared),
            plaintext: h(plaintext),
        },
        channel_message: ChannelMsgVec {
            body: h(ch_body),
            channel_ref: [100, 2],
            reply_to: [99, 1],
            continues: [0, 0],
            remark: h(&ch_remark),
        },
        channel_create: ChannelCreateVec {
            name: "general".into(),
            description: "General discussion".into(),
            remark: h(&create_remark),
        },
        group_message: GroupMsgVec {
            nonce: h(&group_nonce),
            members: group_members.iter().map(|p| h(p)).collect(),
            body: h(group_body),
            member_list_encoded: h(&member_list_encoded),
            root_plaintext: h(&group_inner),
            content_key: h(&content_key),
            eph_pubkey: h(&group_eph_pubkey.to_bytes()),
            capsules: h(&group_capsules),
            ciphertext: h(&group_ciphertext),
            remark: h(&group_remark),
        },
        edge_cases: EdgeCases {
            empty_body_public: h(&empty_body_public),
            min_encrypted: h(&min_enc_remark),
            empty_desc_channel_create: h(&empty_desc_create),
        },
        negative_cases: NegativeCases {
            non_samp_version: format!("0x{non_samp_version}"),
            reserved_type: format!("0x{reserved_type}"),
            truncated_encrypted: format!("0x{truncated_encrypted}"),
        },
    };

    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
