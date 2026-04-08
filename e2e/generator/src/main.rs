use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use serde::Serialize;
use sha2::Sha256;
use std::path::PathBuf;

use samp::encryption;
use samp::extrinsic::{build_signed_extrinsic, ChainParams};
use samp::scale::{decode_compact, encode_compact};
use samp::wire::*;
use samp::{BlockRef, GenesisHash, Nonce, Pubkey, Seed, Signature};

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
    let scalar = encryption::sr25519_signing_scalar(&Seed::from_bytes(*seed));
    KeypairVec {
        seed: h(seed),
        sr25519_public: h(&kp.public.to_bytes()),
        signing_scalar: h(&scalar.to_bytes()),
    }
}

fn main() {
    let alice_seed_bytes: [u8; 32] =
        hex::decode("e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a")
            .unwrap()
            .try_into()
            .unwrap();
    let bob_seed_bytes: [u8; 32] =
        hex::decode("398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89")
            .unwrap()
            .try_into()
            .unwrap();
    let charlie_seed_bytes: [u8; 32] = [0xCC; 32];
    let nonce_bytes: [u8; 12] = hex::decode("a1b2c3d4e5f6a7b8c9d0e1f2")
        .unwrap()
        .try_into()
        .unwrap();
    let alice_seed = Seed::from_bytes(alice_seed_bytes);
    let bob_seed = Seed::from_bytes(bob_seed_bytes);
    let charlie_seed = Seed::from_bytes(charlie_seed_bytes);
    let nonce = Nonce::from_bytes(nonce_bytes);

    let alice_msk = MiniSecretKey::from_bytes(&alice_seed_bytes).unwrap();
    let alice_kp = alice_msk.expand_to_keypair(ExpansionMode::Ed25519);
    let bob_msk = MiniSecretKey::from_bytes(&bob_seed_bytes).unwrap();
    let bob_kp = bob_msk.expand_to_keypair(ExpansionMode::Ed25519);
    let bob_pub = bob_kp.public.to_bytes();
    let bob_pubkey = Pubkey::from_bytes(bob_pub);
    let bob_scalar = encryption::sr25519_signing_scalar(&bob_seed);

    let charlie_pub = encryption::public_from_seed(&charlie_seed);
    let charlie_scalar = encryption::sr25519_signing_scalar(&charlie_seed);

    // === Public message ===
    let body = b"Hello";
    let public_remark = encode_public(&bob_pubkey, body);

    // === Encrypted message with full intermediates ===
    let plaintext = b"Hello Bob";

    let eph_hk = Hkdf::<Sha256>::new(None, &alice_seed_bytes);
    let mut eph_info = [0u8; 44];
    eph_info[..32].copy_from_slice(&bob_pub);
    eph_info[32..].copy_from_slice(&nonce_bytes);
    let mut ephemeral_bytes = [0u8; 32];
    eph_hk.expand(&eph_info, &mut ephemeral_bytes).unwrap();
    let eph_scalar = Scalar::from_bytes_mod_order(ephemeral_bytes);
    let eph_pubkey = (eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();

    let bob_point = bob_pubkey.to_compressed_ristretto().decompress().unwrap();
    let shared_secret = (eph_scalar * bob_point).compress().to_bytes();

    let vt_hk = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut vt_buf = [0u8; 1];
    vt_hk.expand(b"samp-view-tag", &mut vt_buf).unwrap();
    let view_tag = vt_buf[0];

    let seal_hk = Hkdf::<Sha256>::new(Some(&nonce_bytes), &alice_seed_bytes);
    let mut seal_key = [0u8; 32];
    seal_hk.expand(b"samp-seal", &mut seal_key).unwrap();
    let mut sealed_to = [0u8; 32];
    for i in 0..32 {
        sealed_to[i] = bob_pub[i] ^ seal_key[i];
    }

    let sym_hk = Hkdf::<Sha256>::new(Some(&nonce_bytes), &shared_secret);
    let mut symmetric_key = [0u8; 32];
    sym_hk.expand(b"samp-message", &mut symmetric_key).unwrap();

    let cipher = ChaCha20Poly1305::new((&symmetric_key).into());
    let manual_ct = cipher
        .encrypt(
            ChaChaNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_slice(),
                aad: &sealed_to,
            },
        )
        .unwrap();

    let encrypted_content = encryption::encrypt(plaintext, &bob_pubkey, &nonce, &alice_seed).unwrap();
    let ciphertext_with_tag = &encrypted_content[64..];
    assert_eq!(ciphertext_with_tag, manual_ct.as_slice());
    assert_eq!(&encrypted_content[..32], eph_pubkey.to_bytes());
    assert_eq!(&encrypted_content[32..64], sealed_to);

    let enc_remark = encode_encrypted(ContentType::Encrypted, view_tag, &nonce, &encrypted_content);

    let samp::Remark::Encrypted(parsed) = decode_remark(&enc_remark).unwrap() else {
        panic!("expected Encrypted");
    };
    let decrypted = encryption::decrypt(&parsed, &bob_scalar).unwrap();
    assert_eq!(&decrypted, plaintext);

    // === Thread message ===
    let thread_ref = BlockRef { block: 100, index: 0 };
    let reply_to_ref = BlockRef { block: 101, index: 1 };
    let continues_ref = BlockRef { block: 100, index: 0 };
    let thread_body = b"Re: subnet 7";
    let thread_plaintext =
        encode_thread_content(thread_ref, reply_to_ref, continues_ref, thread_body);
    let thread_nonce_bytes: [u8; 12] = hex::decode("b1c2d3e4f5a6b7c8d9e0f1a2")
        .unwrap()
        .try_into()
        .unwrap();
    let thread_nonce = Nonce::from_bytes(thread_nonce_bytes);

    let thread_encrypted =
        encryption::encrypt(&thread_plaintext, &bob_pubkey, &thread_nonce, &alice_seed).unwrap();
    let thread_view_tag =
        encryption::compute_view_tag(&alice_seed, &bob_pubkey, &thread_nonce).unwrap();
    let thread_remark = encode_encrypted(
        ContentType::Thread,
        thread_view_tag,
        &thread_nonce,
        &thread_encrypted,
    );

    let samp::Remark::Thread(thread_parsed) = decode_remark(&thread_remark).unwrap() else {
        panic!("expected Thread");
    };
    let thread_decrypted = encryption::decrypt(&thread_parsed, &bob_scalar).unwrap();
    assert_eq!(thread_decrypted, thread_plaintext);

    // === Sender self-decryption intermediates ===
    let sd_seal_hk = Hkdf::<Sha256>::new(Some(&nonce_bytes), &alice_seed_bytes);
    let mut sd_seal_key = [0u8; 32];
    sd_seal_hk.expand(b"samp-seal", &mut sd_seal_key).unwrap();
    let sd_sealed_to: [u8; 32] = encrypted_content[32..64].try_into().unwrap();
    let mut sd_recipient = [0u8; 32];
    for i in 0..32 {
        sd_recipient[i] = sd_sealed_to[i] ^ sd_seal_key[i];
    }
    assert_eq!(sd_recipient, bob_pub);

    let sd_eph_hk = Hkdf::<Sha256>::new(None, &alice_seed_bytes);
    let mut sd_eph_info = [0u8; 44];
    sd_eph_info[..32].copy_from_slice(&sd_recipient);
    sd_eph_info[32..].copy_from_slice(&nonce_bytes);
    let mut sd_eph_bytes = [0u8; 32];
    sd_eph_hk.expand(&sd_eph_info, &mut sd_eph_bytes).unwrap();
    let sd_eph_scalar = Scalar::from_bytes_mod_order(sd_eph_bytes);
    let sd_recip_point = curve25519_dalek::ristretto::CompressedRistretto(sd_recipient)
        .decompress()
        .unwrap();
    let sd_shared = (sd_eph_scalar * sd_recip_point).compress().to_bytes();

    let sd_decrypted = encryption::decrypt_as_sender(&parsed, &alice_seed).unwrap();
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
    let group_nonce_bytes: [u8; 12] = [0xCC; 12];
    let group_nonce = Nonce::from_bytes(group_nonce_bytes);
    let group_body = b"Hello group";
    let alice_pub = alice_kp.public.to_bytes();
    let group_members: Vec<Pubkey> = vec![
        Pubkey::from_bytes(alice_pub),
        Pubkey::from_bytes(bob_pub),
        charlie_pub,
    ];
    let member_list_encoded = encode_group_members(&group_members);

    let mut root_plaintext = member_list_encoded.clone();
    root_plaintext.extend_from_slice(group_body);

    let group_inner =
        encode_thread_content(BlockRef::ZERO, BlockRef::ZERO, BlockRef::ZERO, &root_plaintext);

    let content_key: [u8; 32] = [0xDD; 32];
    let group_eph_scalar = encryption::derive_group_ephemeral(&alice_seed, &group_nonce);
    let group_eph_pubkey = (group_eph_scalar * RISTRETTO_BASEPOINT_POINT).compress();
    let group_capsules = encryption::build_capsules(
        &content_key,
        &group_members,
        &group_eph_scalar,
        &group_nonce,
    );

    let group_cipher = ChaCha20Poly1305::new((&content_key).into());
    let group_ciphertext = group_cipher
        .encrypt(ChaChaNonce::from_slice(&group_nonce_bytes), group_inner.as_slice())
        .expect("group encryption");

    let group_eph_pubkey_pk = Pubkey::from_bytes(group_eph_pubkey.to_bytes());
    let group_remark = encode_group(
        &group_nonce,
        &group_eph_pubkey_pk,
        &group_capsules,
        &group_ciphertext,
    );

    let group_content = &group_remark[13..];
    let bob_decrypted =
        encryption::decrypt_from_group(group_content, &bob_scalar, &group_nonce, Some(3)).unwrap();
    assert_eq!(bob_decrypted, group_inner);

    let charlie_decrypted =
        encryption::decrypt_from_group(group_content, &charlie_scalar, &group_nonce, Some(3))
            .unwrap();
    assert_eq!(charlie_decrypted, group_inner);

    let random_seed = Seed::from_bytes([0xEE; 32]);
    let random_scalar = encryption::sr25519_signing_scalar(&random_seed);
    assert!(
        encryption::decrypt_from_group(group_content, &random_scalar, &group_nonce, Some(3))
            .is_err()
    );

    // === Edge cases ===
    let empty_body_public = encode_public(&bob_pubkey, b"");
    let min_encrypted = encryption::encrypt(b"", &bob_pubkey, &nonce, &alice_seed).unwrap();
    let min_enc_remark = encode_encrypted(ContentType::Encrypted, view_tag, &nonce, &min_encrypted);
    let empty_desc_create = encode_channel_create("test", "").unwrap();

    // === Negative cases ===
    let non_samp_version = format!("0x{}", hex::encode([0x21u8, 0x00]));
    let reserved_type = format!("0x{}", hex::encode([0x17u8]));
    let truncated_encrypted = format!("0x{}", hex::encode([0x12u8, 0x00, 0x01, 0x02]));

    let scale_vectors = build_scale_vectors();
    let extrinsic_vectors = build_extrinsic_vectors(&alice_kp, &alice_seed_bytes);

    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("e2e directory");

    std::fs::write(
        out_dir.join("scale-vectors.json"),
        serde_json::to_string_pretty(&scale_vectors).unwrap(),
    )
    .expect("write scale-vectors.json");
    std::fs::write(
        out_dir.join("extrinsic-vectors.json"),
        serde_json::to_string_pretty(&extrinsic_vectors).unwrap(),
    )
    .expect("write extrinsic-vectors.json");

    let vectors = TestVectors {
        alice: make_keypair_vec(&alice_seed_bytes),
        bob: make_keypair_vec(&bob_seed_bytes),
        charlie: make_keypair_vec(&charlie_seed_bytes),
        public_message: PublicMsgVec {
            body: h(body),
            remark: h(&public_remark),
        },
        encrypted_message: EncryptedMsgVec {
            nonce: h(&nonce_bytes),
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
            nonce: h(&thread_nonce_bytes),
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
            nonce: h(&group_nonce_bytes),
            members: group_members.iter().map(|p| h(p.as_bytes())).collect(),
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
            non_samp_version,
            reserved_type,
            truncated_encrypted,
        },
    };

    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}

#[derive(Serialize)]
struct ScaleCompactVec {
    value: String,
    encoded: String,
    consumed: usize,
}

#[derive(Serialize)]
struct ScaleVectors {
    compact: Vec<ScaleCompactVec>,
}

fn build_scale_vectors() -> ScaleVectors {
    let probes: [u64; 12] = [
        0,
        1,
        63,
        64,
        16_383,
        16_384,
        (1 << 30) - 1,
        1 << 30,
        u64::from(u32::MAX),
        1u64 << 32,
        1u64 << 56,
        u64::MAX,
    ];
    let compact = probes
        .iter()
        .map(|&value| {
            let mut encoded = Vec::new();
            encode_compact(value, &mut encoded);
            let (decoded, consumed) = decode_compact(&encoded).expect("round-trip");
            assert_eq!(decoded, value);
            ScaleCompactVec {
                value: value.to_string(),
                encoded: h(&encoded),
                consumed,
            }
        })
        .collect();
    ScaleVectors { compact }
}

#[derive(Serialize)]
struct ChainParamsVec {
    genesis_hash: String,
    spec_version: u32,
    tx_version: u32,
}

#[derive(Serialize)]
struct ExtrinsicCaseVec {
    label: &'static str,
    pallet_idx: u8,
    call_idx: u8,
    call_args: String,
    public_key: String,
    fixed_signature: String,
    nonce: u32,
    chain_params: ChainParamsVec,
    expected_extrinsic: String,
}

#[derive(Serialize)]
struct ExtrinsicVectors {
    cases: Vec<ExtrinsicCaseVec>,
}

fn build_extrinsic_vectors(alice_kp: &schnorrkel::Keypair, _alice_seed: &[u8; 32]) -> ExtrinsicVectors {
    let public_key = Pubkey::from_bytes(alice_kp.public.to_bytes());
    let chain = ChainParams {
        genesis_hash: GenesisHash::from_bytes([0x11; 32]),
        spec_version: 100,
        tx_version: 1,
    };
    let fixed_signature = Signature::from_bytes([0xAB; 64]);

    let long_payload = vec![0xCD; 1024];
    let cases = vec![
        build_case(CaseInputs {
            label: "system_remark_with_event_short",
            pallet_idx: 0,
            call_idx: 7,
            remark: b"hi",
            public_key: &public_key,
            fixed_signature: &fixed_signature,
            nonce: 0,
            chain: &chain,
        }),
        build_case(CaseInputs {
            label: "system_remark_with_event_empty",
            pallet_idx: 0,
            call_idx: 7,
            remark: b"",
            public_key: &public_key,
            fixed_signature: &fixed_signature,
            nonce: 1,
            chain: &chain,
        }),
        build_case(CaseInputs {
            label: "system_remark_with_event_long",
            pallet_idx: 0,
            call_idx: 7,
            remark: &long_payload,
            public_key: &public_key,
            fixed_signature: &fixed_signature,
            nonce: 42,
            chain: &chain,
        }),
    ];

    ExtrinsicVectors { cases }
}

struct CaseInputs<'a> {
    label: &'static str,
    pallet_idx: u8,
    call_idx: u8,
    remark: &'a [u8],
    public_key: &'a Pubkey,
    fixed_signature: &'a Signature,
    nonce: u32,
    chain: &'a ChainParams,
}

fn build_case(c: CaseInputs<'_>) -> ExtrinsicCaseVec {
    let mut call_args = Vec::new();
    encode_compact(c.remark.len() as u64, &mut call_args);
    call_args.extend_from_slice(c.remark);

    let extrinsic = build_signed_extrinsic(
        c.pallet_idx,
        c.call_idx,
        &call_args,
        c.public_key,
        |_msg| *c.fixed_signature,
        c.nonce,
        c.chain,
    )
    .expect("build_signed_extrinsic");

    ExtrinsicCaseVec {
        label: c.label,
        pallet_idx: c.pallet_idx,
        call_idx: c.call_idx,
        call_args: h(&call_args),
        public_key: h(c.public_key.as_bytes()),
        fixed_signature: h(c.fixed_signature.as_bytes()),
        nonce: c.nonce,
        chain_params: ChainParamsVec {
            genesis_hash: h(c.chain.genesis_hash.as_bytes()),
            spec_version: c.chain.spec_version,
            tx_version: c.chain.tx_version,
        },
        expected_extrinsic: h(&extrinsic),
    }
}
