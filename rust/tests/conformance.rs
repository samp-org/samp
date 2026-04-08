#![allow(dead_code)]

use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use serde::Deserialize;
use std::path::Path;

use samp::encryption;
use samp::secret::Seed;
use samp::types::*;
use samp::wire::*;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

fn h12(s: &str) -> [u8; 12] {
    h(s).try_into().unwrap()
}

fn seed(s: &str) -> Seed {
    Seed::from_bytes(h32(s))
}

fn pubkey(s: &str) -> Pubkey {
    Pubkey::from_bytes(h32(s))
}

fn nonce(s: &str) -> Nonce {
    Nonce::from_bytes(h12(s))
}

fn br(b: u32, i: u16) -> BlockRef {
    BlockRef { block: b, index: i }
}

#[derive(Deserialize)]
struct KeypairVec {
    seed: String,
    sr25519_public: String,
    signing_scalar: String,
}

#[derive(Deserialize)]
struct PublicMsgVec {
    body: String,
    remark: String,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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

#[derive(Deserialize)]
struct SenderDecryptVec {
    seal_key: String,
    unsealed_recipient: String,
    re_derived_ephemeral_bytes: String,
    re_derived_shared_secret: String,
    plaintext: String,
}

#[derive(Deserialize)]
struct ChannelMsgVec {
    body: String,
    channel_ref: [u32; 2],
    reply_to: [u32; 2],
    continues: [u32; 2],
    remark: String,
}

#[derive(Deserialize)]
struct ChannelCreateVec {
    name: String,
    description: String,
    remark: String,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
struct EdgeCases {
    empty_body_public: String,
    min_encrypted: String,
    empty_desc_channel_create: String,
}

#[derive(Deserialize)]
struct NegativeCases {
    non_samp_version: String,
    reserved_type: String,
    truncated_encrypted: String,
}

#[derive(Deserialize)]
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

fn load_vectors() -> TestVectors {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../e2e/test-vectors.json");
    let data = std::fs::read_to_string(path).expect("test-vectors.json");
    serde_json::from_str(&data).expect("valid JSON")
}

#[test]
fn conformance_keypair_alice() {
    let v = load_vectors();
    let seed_bytes = h32(&v.alice.seed);
    let msk = MiniSecretKey::from_bytes(&seed_bytes).unwrap();
    let kp = msk.expand_to_keypair(ExpansionMode::Ed25519);
    assert_eq!(kp.public.to_bytes(), h32(&v.alice.sr25519_public));
    let scalar = encryption::sr25519_signing_scalar(&seed(&v.alice.seed));
    assert_eq!(scalar.to_bytes(), h32(&v.alice.signing_scalar));
}

#[test]
fn conformance_keypair_bob() {
    let v = load_vectors();
    let seed_bytes = h32(&v.bob.seed);
    let msk = MiniSecretKey::from_bytes(&seed_bytes).unwrap();
    let kp = msk.expand_to_keypair(ExpansionMode::Ed25519);
    assert_eq!(kp.public.to_bytes(), h32(&v.bob.sr25519_public));
    let scalar = encryption::sr25519_signing_scalar(&seed(&v.bob.seed));
    assert_eq!(scalar.to_bytes(), h32(&v.bob.signing_scalar));
}

#[test]
fn conformance_public_message_encode() {
    let v = load_vectors();
    let bob_pub = pubkey(&v.bob.sr25519_public);
    let remark = encode_public(&bob_pub, &h(&v.public_message.body));
    assert_eq!(remark, h(&v.public_message.remark));
}

#[test]
fn conformance_public_message_decode() {
    let v = load_vectors();
    let parsed = decode_remark(&h(&v.public_message.remark)).unwrap();
    assert_eq!(parsed.content_type, ContentType::Public);
    assert_eq!(parsed.content, h(&v.public_message.body));
}

#[test]
fn conformance_encrypted_encode() {
    let v = load_vectors();
    let alice_seed = seed(&v.alice.seed);
    let bob_pubkey = pubkey(&v.bob.sr25519_public);
    let n = nonce(&v.encrypted_message.nonce);
    let plaintext = h(&v.encrypted_message.plaintext);

    let content = encryption::encrypt(&plaintext, &bob_pubkey, &n, &alice_seed).unwrap();
    assert_eq!(content, h(&v.encrypted_message.encrypted_content));

    let vt = encryption::compute_view_tag(&alice_seed, &bob_pubkey, &n).unwrap();
    assert_eq!(vt, v.encrypted_message.view_tag);

    let remark = encode_encrypted(ContentType::Encrypted, vt, &n, &content);
    assert_eq!(remark, h(&v.encrypted_message.remark));
}

#[test]
fn conformance_encrypted_intermediates() {
    let v = load_vectors();
    // Verify each intermediate value matches the test vector
    let content = h(&v.encrypted_message.encrypted_content);
    assert_eq!(
        &content[..32],
        h(&v.encrypted_message.ephemeral_pubkey).as_slice()
    );
    assert_eq!(
        &content[32..64],
        h(&v.encrypted_message.sealed_to).as_slice()
    );
    assert_eq!(
        &content[64..],
        h(&v.encrypted_message.ciphertext_with_tag).as_slice()
    );
}

#[test]
fn conformance_encrypted_recipient_decrypt() {
    let v = load_vectors();
    let bob_scalar = encryption::sr25519_signing_scalar(&seed(&v.bob.seed));
    let remark_bytes = h(&v.encrypted_message.remark);
    let parsed = decode_remark(&remark_bytes).unwrap();
    let plaintext = encryption::decrypt(&parsed, &bob_scalar).unwrap();
    assert_eq!(plaintext, h(&v.encrypted_message.plaintext));
}

#[test]
fn conformance_sender_self_decrypt() {
    let v = load_vectors();
    let alice_seed = seed(&v.alice.seed);
    let remark_bytes = h(&v.encrypted_message.remark);
    let parsed = decode_remark(&remark_bytes).unwrap();
    let plaintext = encryption::decrypt_as_sender(&parsed, &alice_seed).unwrap();
    assert_eq!(plaintext, h(&v.sender_self_decryption.plaintext));

    assert_eq!(
        h(&v.sender_self_decryption.unsealed_recipient),
        h(&v.bob.sr25519_public)
    );
}

#[test]
fn conformance_thread_message() {
    let v = load_vectors();
    let alice_seed = seed(&v.alice.seed);
    let bob_pubkey = pubkey(&v.bob.sr25519_public);
    let bob_scalar = encryption::sr25519_signing_scalar(&seed(&v.bob.seed));
    let n = nonce(&v.thread_message.nonce);

    let th = v.thread_message.thread_ref;
    let rt = v.thread_message.reply_to;
    let ct = v.thread_message.continues;
    let thread_plaintext = encode_thread_content(
        br(th[0], th[1] as u16),
        br(rt[0], rt[1] as u16),
        br(ct[0], ct[1] as u16),
        &h(&v.thread_message.body),
    );
    assert_eq!(thread_plaintext, h(&v.thread_message.thread_plaintext));

    let encrypted =
        encryption::encrypt(&thread_plaintext, &bob_pubkey, &n, &alice_seed).unwrap();
    assert_eq!(encrypted, h(&v.thread_message.encrypted_content));

    let vt = encryption::compute_view_tag(&alice_seed, &bob_pubkey, &n).unwrap();
    let remark_bytes = encode_encrypted(ContentType::Thread, vt, &n, &encrypted);
    let parsed_remark = decode_remark(&remark_bytes).unwrap();
    let decrypted = encryption::decrypt(&parsed_remark, &bob_scalar).unwrap();
    let (thread, reply_to, continues, body) = decode_thread_content(&decrypted).unwrap();
    assert_eq!(thread.block, th[0]);
    assert_eq!(reply_to.block, rt[0]);
    assert_eq!(continues.block, ct[0]);
    assert_eq!(body, h(&v.thread_message.body));
}

#[test]
fn conformance_channel_message() {
    let v = load_vectors();
    let ch = &v.channel_message;
    let remark = encode_channel_msg(
        br(ch.channel_ref[0], ch.channel_ref[1] as u16),
        br(ch.reply_to[0], ch.reply_to[1] as u16),
        br(ch.continues[0], ch.continues[1] as u16),
        &h(&ch.body),
    );
    assert_eq!(remark, h(&ch.remark));
}

#[test]
fn conformance_channel_create() {
    let v = load_vectors();
    let remark =
        encode_channel_create(&v.channel_create.name, &v.channel_create.description).unwrap();
    assert_eq!(remark, h(&v.channel_create.remark));

    let parsed = decode_remark(&remark).unwrap();
    let (name, desc) = decode_channel_create(&parsed.content).unwrap();
    assert_eq!(name, v.channel_create.name);
    assert_eq!(desc, v.channel_create.description);
}

#[test]
fn conformance_edge_empty_body_public() {
    let v = load_vectors();
    let remark = h(&v.edge_cases.empty_body_public);
    let parsed = decode_remark(&remark).unwrap();
    assert_eq!(parsed.content_type, ContentType::Public);
    assert!(parsed.content.is_empty());
}

#[test]
fn conformance_edge_min_encrypted() {
    let v = load_vectors();
    let remark = h(&v.edge_cases.min_encrypted);
    let parsed = decode_remark(&remark).unwrap();
    assert!(matches!(parsed.content_type, ContentType::Encrypted));
}

#[test]
fn conformance_edge_empty_desc_channel_create() {
    let v = load_vectors();
    let remark = h(&v.edge_cases.empty_desc_channel_create);
    let parsed = decode_remark(&remark).unwrap();
    let (name, desc) = decode_channel_create(&parsed.content).unwrap();
    assert_eq!(name, "test");
    assert_eq!(desc, "");
}

#[test]
fn conformance_group_message_remark() {
    let v = load_vectors();
    let remark_bytes = h(&v.group_message.remark);
    let parsed = decode_remark(&remark_bytes).unwrap();
    assert!(matches!(parsed.content_type, ContentType::Group));
    assert_eq!(parsed.nonce, nonce(&v.group_message.nonce));
}

#[test]
fn conformance_group_member_list() {
    let v = load_vectors();
    // member_list_encoded is just encode_group_members (no body appended)
    let encoded = h(&v.group_message.member_list_encoded);
    let (members, remaining) = decode_group_members(&encoded).unwrap();
    assert_eq!(members.len(), v.group_message.members.len());
    for (i, m) in members.iter().enumerate() {
        assert_eq!(m.as_bytes(), &h32(&v.group_message.members[i]));
    }
    assert!(remaining.is_empty());
}

#[test]
fn conformance_group_decrypt_by_member() {
    let v = load_vectors();
    let remark_bytes = h(&v.group_message.remark);
    let parsed = decode_remark(&remark_bytes).unwrap();
    let bob_scalar = encryption::sr25519_signing_scalar(&seed(&v.bob.seed));
    let plaintext =
        encryption::decrypt_from_group(&parsed.content, &bob_scalar, &parsed.nonce, Some(3))
            .unwrap();
    let root_plaintext = h(&v.group_message.root_plaintext);
    assert_eq!(plaintext, root_plaintext);
}

#[test]
fn conformance_negative_non_samp_version() {
    let v = load_vectors();
    assert!(decode_remark(&h(&v.negative_cases.non_samp_version)).is_err());
}

#[test]
fn conformance_negative_reserved_type() {
    let v = load_vectors();
    assert!(decode_remark(&h(&v.negative_cases.reserved_type)).is_err());
}

#[test]
fn conformance_negative_truncated_encrypted() {
    let v = load_vectors();
    assert!(decode_remark(&h(&v.negative_cases.truncated_encrypted)).is_err());
}
