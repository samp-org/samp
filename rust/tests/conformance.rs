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

fn rb(s: &str) -> RemarkBytes {
    RemarkBytes::from_bytes(h(s))
}

fn pt(s: &str) -> Plaintext {
    Plaintext::from_bytes(h(s))
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
    BlockRef::from_parts(b, i)
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
    let body = String::from_utf8(h(&v.public_message.body)).unwrap();
    let remark = encode_public(&bob_pub, &body);
    assert_eq!(remark.as_bytes(), h(&v.public_message.remark).as_slice());
}

#[test]
fn conformance_public_message_decode() {
    let v = load_vectors();
    let Remark::Public { body, .. } = decode_remark(&rb(&v.public_message.remark)).unwrap() else {
        panic!("expected Public");
    };
    assert_eq!(body.as_bytes(), h(&v.public_message.body).as_slice());
}

#[test]
fn conformance_encrypted_encode() {
    let v = load_vectors();
    let alice_seed = seed(&v.alice.seed);
    let bob_pubkey = pubkey(&v.bob.sr25519_public);
    let n = nonce(&v.encrypted_message.nonce);
    let plaintext = pt(&v.encrypted_message.plaintext);

    let content = encryption::encrypt(&plaintext, &bob_pubkey, &n, &alice_seed).unwrap();
    assert_eq!(content.as_bytes(), h(&v.encrypted_message.encrypted_content).as_slice());

    let vt = encryption::compute_view_tag(&alice_seed, &bob_pubkey, &n).unwrap();
    assert_eq!(vt.get(), v.encrypted_message.view_tag);

    let remark = encode_encrypted(ContentType::Encrypted, vt, &n, &content);
    assert_eq!(remark.as_bytes(), h(&v.encrypted_message.remark).as_slice());
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
    let remark_bytes = rb(&v.encrypted_message.remark);
    let Remark::Encrypted(payload) = decode_remark(&remark_bytes).unwrap() else {
        panic!("expected Encrypted");
    };
    let plaintext = encryption::decrypt(&payload, &bob_scalar).unwrap();
    assert_eq!(plaintext.as_bytes(), h(&v.encrypted_message.plaintext).as_slice());
}

#[test]
fn conformance_sender_self_decrypt() {
    let v = load_vectors();
    let alice_seed = seed(&v.alice.seed);
    let remark_bytes = rb(&v.encrypted_message.remark);
    let Remark::Encrypted(payload) = decode_remark(&remark_bytes).unwrap() else {
        panic!("expected Encrypted");
    };
    let plaintext = encryption::decrypt_as_sender(&payload, &alice_seed).unwrap();
    assert_eq!(plaintext.as_bytes(), h(&v.sender_self_decryption.plaintext).as_slice());

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
        encryption::encrypt(&Plaintext::from_bytes(thread_plaintext.clone()), &bob_pubkey, &n, &alice_seed).unwrap();
    assert_eq!(encrypted.as_bytes(), h(&v.thread_message.encrypted_content).as_slice());

    let vt = encryption::compute_view_tag(&alice_seed, &bob_pubkey, &n).unwrap();
    let remark_bytes = encode_encrypted(ContentType::Thread, vt, &n, &encrypted);
    let Remark::Thread(payload) = decode_remark(&remark_bytes).unwrap() else {
        panic!("expected Thread");
    };
    let decrypted = encryption::decrypt(&payload, &bob_scalar).unwrap();
    let (thread, reply_to, continues, body) = decode_thread_content(decrypted.as_bytes()).unwrap();
    assert_eq!(thread.block().get(), th[0]);
    assert_eq!(reply_to.block().get(), rt[0]);
    assert_eq!(continues.block().get(), ct[0]);
    assert_eq!(body, h(&v.thread_message.body));
}

#[test]
fn conformance_channel_message() {
    let v = load_vectors();
    let ch = &v.channel_message;
    let body = String::from_utf8(h(&ch.body)).unwrap();
    let remark = encode_channel_msg(
        br(ch.channel_ref[0], ch.channel_ref[1] as u16),
        br(ch.reply_to[0], ch.reply_to[1] as u16),
        br(ch.continues[0], ch.continues[1] as u16),
        &body,
    );
    assert_eq!(remark.as_bytes(), h(&ch.remark).as_slice());
}

#[test]
fn conformance_channel_create() {
    let v = load_vectors();
    let name = ChannelName::parse(v.channel_create.name.clone()).unwrap();
    let desc = ChannelDescription::parse(v.channel_create.description.clone()).unwrap();
    let remark = encode_channel_create(&name, &desc);
    assert_eq!(remark.as_bytes(), h(&v.channel_create.remark).as_slice());

    let Remark::ChannelCreate { name, description } = decode_remark(&remark).unwrap() else {
        panic!("expected ChannelCreate");
    };
    assert_eq!(name.as_str(), v.channel_create.name);
    assert_eq!(description.as_str(), v.channel_create.description);
}

#[test]
fn conformance_edge_empty_body_public() {
    let v = load_vectors();
    let remark = rb(&v.edge_cases.empty_body_public);
    let Remark::Public { body, .. } = decode_remark(&remark).unwrap() else {
        panic!("expected Public");
    };
    assert!(body.is_empty());
}

#[test]
fn conformance_edge_min_encrypted() {
    let v = load_vectors();
    let remark = rb(&v.edge_cases.min_encrypted);
    let parsed = decode_remark(&remark).unwrap();
    assert!(matches!(parsed, Remark::Encrypted(_)));
}

#[test]
fn conformance_edge_empty_desc_channel_create() {
    let v = load_vectors();
    let remark = rb(&v.edge_cases.empty_desc_channel_create);
    let Remark::ChannelCreate { name, description } = decode_remark(&remark).unwrap() else {
        panic!("expected ChannelCreate");
    };
    assert_eq!(name.as_str(), "test");
    assert_eq!(description.as_str(), "");
}

#[test]
fn conformance_group_message_remark() {
    let v = load_vectors();
    let remark_bytes = rb(&v.group_message.remark);
    let Remark::Group(payload) = decode_remark(&remark_bytes).unwrap() else {
        panic!("expected Group");
    };
    assert_eq!(payload.nonce, nonce(&v.group_message.nonce));
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
    let remark_bytes = rb(&v.group_message.remark);
    let Remark::Group(payload) = decode_remark(&remark_bytes).unwrap() else {
        panic!("expected Group");
    };
    let bob_scalar = encryption::sr25519_signing_scalar(&seed(&v.bob.seed));
    let plaintext =
        encryption::decrypt_from_group(&payload, &bob_scalar, Some(3))
            .unwrap();
    let root_plaintext = h(&v.group_message.root_plaintext);
    assert_eq!(plaintext.as_bytes(), root_plaintext.as_slice());
}

#[test]
fn conformance_negative_non_samp_version() {
    let v = load_vectors();
    assert!(decode_remark(&rb(&v.negative_cases.non_samp_version)).is_err());
}

#[test]
fn conformance_negative_reserved_type() {
    let v = load_vectors();
    assert!(decode_remark(&rb(&v.negative_cases.reserved_type)).is_err());
}

#[test]
fn conformance_negative_truncated_encrypted() {
    let v = load_vectors();
    assert!(decode_remark(&rb(&v.negative_cases.truncated_encrypted)).is_err());
}
