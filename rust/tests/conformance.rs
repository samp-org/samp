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
    assert_eq!(*scalar.expose_secret(), h32(&v.alice.signing_scalar));
}

#[test]
fn conformance_keypair_bob() {
    let v = load_vectors();
    let seed_bytes = h32(&v.bob.seed);
    let msk = MiniSecretKey::from_bytes(&seed_bytes).unwrap();
    let kp = msk.expand_to_keypair(ExpansionMode::Ed25519);
    assert_eq!(kp.public.to_bytes(), h32(&v.bob.sr25519_public));
    let scalar = encryption::sr25519_signing_scalar(&seed(&v.bob.seed));
    assert_eq!(*scalar.expose_secret(), h32(&v.bob.signing_scalar));
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
    assert_eq!(
        content.as_bytes(),
        h(&v.encrypted_message.encrypted_content).as_slice()
    );

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
    let Remark::Encrypted {
        nonce: n_out,
        ciphertext,
        ..
    } = decode_remark(&remark_bytes).unwrap()
    else {
        panic!("expected Encrypted");
    };
    let plaintext = encryption::decrypt(&ciphertext, &n_out, &bob_scalar).unwrap();
    assert_eq!(
        plaintext.as_bytes(),
        h(&v.encrypted_message.plaintext).as_slice()
    );
}

#[test]
fn conformance_sender_self_decrypt() {
    let v = load_vectors();
    let alice_seed = seed(&v.alice.seed);
    let remark_bytes = rb(&v.encrypted_message.remark);
    let Remark::Encrypted {
        nonce: n_out,
        ciphertext,
        ..
    } = decode_remark(&remark_bytes).unwrap()
    else {
        panic!("expected Encrypted");
    };
    let plaintext = encryption::decrypt_as_sender(&ciphertext, &n_out, &alice_seed).unwrap();
    assert_eq!(
        plaintext.as_bytes(),
        h(&v.sender_self_decryption.plaintext).as_slice()
    );

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

    let encrypted = encryption::encrypt(
        &Plaintext::from_bytes(thread_plaintext.clone()),
        &bob_pubkey,
        &n,
        &alice_seed,
    )
    .unwrap();
    assert_eq!(
        encrypted.as_bytes(),
        h(&v.thread_message.encrypted_content).as_slice()
    );

    let vt = encryption::compute_view_tag(&alice_seed, &bob_pubkey, &n).unwrap();
    let remark_bytes = encode_encrypted(ContentType::Thread, vt, &n, &encrypted);
    let Remark::Thread {
        nonce: n_out,
        ciphertext,
        ..
    } = decode_remark(&remark_bytes).unwrap()
    else {
        panic!("expected Thread");
    };
    let decrypted = encryption::decrypt(&ciphertext, &n_out, &bob_scalar).unwrap();
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
    assert!(matches!(parsed, Remark::Encrypted { .. }));
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
    let Remark::Group { nonce: n_out, .. } = decode_remark(&remark_bytes).unwrap() else {
        panic!("expected Group");
    };
    assert_eq!(n_out, nonce(&v.group_message.nonce));
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
    let Remark::Group {
        nonce: n_out,
        content,
    } = decode_remark(&remark_bytes).unwrap()
    else {
        panic!("expected Group");
    };
    let bob_scalar = encryption::sr25519_signing_scalar(&seed(&v.bob.seed));
    let plaintext = encryption::decrypt_from_group(&content, &n_out, &bob_scalar, Some(3)).unwrap();
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

#[test]
fn conformance_content_type_byte_values_pinned() {
    assert_eq!(ContentType::Public.to_byte(), 0x10);
    assert_eq!(ContentType::Encrypted.to_byte(), 0x11);
    assert_eq!(ContentType::Thread.to_byte(), 0x12);
    assert_eq!(ContentType::ChannelCreate.to_byte(), 0x13);
    assert_eq!(ContentType::Channel.to_byte(), 0x14);
    assert_eq!(ContentType::Group.to_byte(), 0x15);
}

#[test]
fn conformance_typed_wrappers_round_trip() {
    let v = load_vectors();
    let bob_raw = h32(&v.bob.sr25519_public);
    assert_eq!(Pubkey::from_bytes(bob_raw).as_bytes(), &bob_raw);
    let nonce_raw = h12(&v.encrypted_message.nonce);
    assert_eq!(Nonce::from_bytes(nonce_raw).as_bytes(), &nonce_raw);
    let gh_raw = h32(&v.alice.sr25519_public);
    assert_eq!(GenesisHash::from_bytes(gh_raw).as_bytes(), &gh_raw);
}

#[test]
fn conformance_block_ref_display_format() {
    let r = BlockRef::from_parts(42, 7);
    assert_eq!(format!("{r:?}"), "#42.7");
}

#[test]
fn conformance_channel_name_parse_empty_rejected() {
    assert!(ChannelName::parse("").is_err());
}

#[test]
fn sr25519_sign_returns_64_bytes() {
    let seed = Seed::from_bytes([0xab; 32]);
    let sig = samp::sr25519_sign(&seed, b"test message");
    assert_eq!(sig.as_bytes().len(), 64);
}

#[test]
fn sr25519_sign_differs_for_different_messages() {
    let seed = Seed::from_bytes([0xab; 32]);
    let a = samp::sr25519_sign(&seed, b"message one");
    let b = samp::sr25519_sign(&seed, b"message two");
    assert_ne!(a.as_bytes(), b.as_bytes());
}

// --- ss58 tests ---

#[test]
fn ss58_encode_decode_round_trip_prefix_42() {
    let pk = Pubkey::from_bytes(h32(
        "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
    ));
    let prefix = Ss58Prefix::new(42).unwrap();
    let addr = Ss58Address::encode(&pk, prefix);
    let decoded = Ss58Address::parse(addr.as_str()).unwrap();
    assert_eq!(decoded.pubkey().as_bytes(), pk.as_bytes());
    assert_eq!(decoded.prefix().get(), 42);
}

#[test]
fn ss58_encode_decode_round_trip_prefix_0() {
    let pk = Pubkey::from_bytes(h32(
        "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
    ));
    let prefix = Ss58Prefix::new(0).unwrap();
    let addr = Ss58Address::encode(&pk, prefix);
    let decoded = Ss58Address::parse(addr.as_str()).unwrap();
    assert_eq!(decoded.pubkey().as_bytes(), pk.as_bytes());
    assert_eq!(decoded.prefix().get(), 0);
}

#[test]
fn ss58_decode_bad_checksum() {
    let pk = Pubkey::from_bytes(h32(
        "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
    ));
    let addr = Ss58Address::encode(&pk, Ss58Prefix::SUBSTRATE_GENERIC);
    let s = addr.as_str();
    let mut chars: Vec<char> = s.chars().collect();
    let last = chars.last_mut().unwrap();
    *last = if *last == 'A' { 'B' } else { 'A' };
    let corrupted: String = chars.into_iter().collect();
    assert!(Ss58Address::parse(&corrupted).is_err());
}

#[test]
fn ss58_decode_too_short() {
    assert!(Ss58Address::parse("5abc").is_err());
}

#[test]
fn ss58_decode_empty() {
    assert!(Ss58Address::parse("").is_err());
}

#[test]
fn ss58_prefix_63_valid() {
    assert!(Ss58Prefix::new(63).is_ok());
}

#[test]
fn ss58_prefix_64_invalid() {
    assert!(Ss58Prefix::new(64).is_err());
}

// --- Phase 2: Types + Secret tests ---

#[test]
fn secret_seed_debug_redacted() {
    let s = Seed::from_bytes([0xAA; 32]);
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("REDACTED"));
}

#[test]
fn secret_view_scalar_debug_redacted() {
    use samp::secret::ViewScalar;
    let vs = ViewScalar::from_bytes([0xBB; 32]);
    let dbg = format!("{:?}", vs);
    assert!(dbg.contains("REDACTED"));
}

#[test]
fn channel_name_parse_too_long() {
    let long: String = "a".repeat(33);
    assert!(ChannelName::parse(long).is_err());
}

#[test]
fn channel_name_parse_valid() {
    assert!(ChannelName::parse("test").is_ok());
}

#[test]
fn channel_desc_parse_too_long() {
    let long: String = "a".repeat(129);
    assert!(ChannelDescription::parse(long).is_err());
}

#[test]
fn block_ref_is_zero() {
    assert!(BlockRef::ZERO.is_zero());
}

#[test]
fn block_ref_from_parts_not_zero() {
    assert!(!BlockRef::from_parts(1, 0).is_zero());
}

// --- Phase 3: Encryption edge cases ---

#[test]
fn decrypt_with_wrong_key_fails() {
    let sender_seed = Seed::from_bytes([0xAA; 32]);
    let recipient_seed = Seed::from_bytes([0xBB; 32]);
    let wrong_seed = Seed::from_bytes([0xCC; 32]);
    let n = Nonce::from_bytes([0x01; 12]);

    let recipient_pub = encryption::public_from_seed(&recipient_seed);
    let plaintext = Plaintext::from_bytes(b"hello".to_vec());
    let ct = encryption::encrypt(&plaintext, &recipient_pub, &n, &sender_seed).unwrap();

    let wrong_scalar = encryption::sr25519_signing_scalar(&wrong_seed);
    assert!(encryption::decrypt(&ct, &n, &wrong_scalar).is_err());
}

#[test]
fn encrypt_decrypt_as_sender_round_trip() {
    let sender_seed = Seed::from_bytes([0xAA; 32]);
    let recipient_seed = Seed::from_bytes([0xBB; 32]);
    let n = Nonce::from_bytes([0x01; 12]);

    let recipient_pub = encryption::public_from_seed(&recipient_seed);
    let plaintext = Plaintext::from_bytes(b"sender round trip".to_vec());
    let ct = encryption::encrypt(&plaintext, &recipient_pub, &n, &sender_seed).unwrap();

    let recovered = encryption::decrypt_as_sender(&ct, &n, &sender_seed).unwrap();
    assert_eq!(recovered.as_bytes(), plaintext.as_bytes());
}

#[test]
fn unseal_recipient_recovers_pubkey() {
    let sender_seed = Seed::from_bytes([0xAA; 32]);
    let recipient_seed = Seed::from_bytes([0xBB; 32]);
    let n = Nonce::from_bytes([0x01; 12]);

    let recipient_pub = encryption::public_from_seed(&recipient_seed);
    let plaintext = Plaintext::from_bytes(b"unseal test".to_vec());
    let ct = encryption::encrypt(&plaintext, &recipient_pub, &n, &sender_seed).unwrap();

    let unsealed = encryption::unseal_recipient(&ct, &n, &sender_seed).unwrap();
    assert_eq!(unsealed.as_bytes(), recipient_pub.as_bytes());
}

#[test]
fn view_tag_mismatch_for_wrong_key() {
    let sender_seed = Seed::from_bytes([0xAA; 32]);
    let recipient_seed = Seed::from_bytes([0xBB; 32]);
    let wrong_seed = Seed::from_bytes([0xCC; 32]);
    let n = Nonce::from_bytes([0x01; 12]);

    let recipient_pub = encryption::public_from_seed(&recipient_seed);
    let plaintext = Plaintext::from_bytes(b"view tag test".to_vec());
    let ct = encryption::encrypt(&plaintext, &recipient_pub, &n, &sender_seed).unwrap();

    let sender_tag = encryption::compute_view_tag(&sender_seed, &recipient_pub, &n).unwrap();
    let wrong_scalar = encryption::sr25519_signing_scalar(&wrong_seed);
    let wrong_tag = encryption::check_view_tag(&ct, &wrong_scalar).unwrap();

    assert_ne!(sender_tag.get(), wrong_tag.get());
}

#[test]
fn group_encrypt_single_member() {
    let sender_seed = Seed::from_bytes([0xAA; 32]);
    let member_seed = Seed::from_bytes([0xBB; 32]);
    let n = Nonce::from_bytes([0x01; 12]);

    let member_pub = encryption::public_from_seed(&member_seed);
    let plaintext = Plaintext::from_bytes(b"group single member".to_vec());

    let (eph_pub, capsules, ciphertext) =
        encryption::encrypt_for_group(&plaintext, &[member_pub], &n, &sender_seed).unwrap();

    let remark = encode_group(&n, &eph_pub, &capsules, &ciphertext);
    let Remark::Group { nonce, content } = decode_remark(&remark).unwrap() else {
        panic!("expected Group");
    };

    let member_scalar = encryption::sr25519_signing_scalar(&member_seed);
    let recovered = encryption::decrypt_from_group(&content, &nonce, &member_scalar, Some(1)).unwrap();
    assert_eq!(recovered.as_bytes(), plaintext.as_bytes());
}

#[test]
fn group_decrypt_wrong_key_fails() {
    let sender_seed = Seed::from_bytes([0xAA; 32]);
    let member_seed = Seed::from_bytes([0xBB; 32]);
    let wrong_seed = Seed::from_bytes([0xCC; 32]);
    let n = Nonce::from_bytes([0x01; 12]);

    let member_pub = encryption::public_from_seed(&member_seed);
    let plaintext = Plaintext::from_bytes(b"group wrong key".to_vec());

    let (eph_pub, capsules, ciphertext) =
        encryption::encrypt_for_group(&plaintext, &[member_pub], &n, &sender_seed).unwrap();

    let remark = encode_group(&n, &eph_pub, &capsules, &ciphertext);
    let Remark::Group { nonce, content } = decode_remark(&remark).unwrap() else {
        panic!("expected Group");
    };

    let wrong_scalar = encryption::sr25519_signing_scalar(&wrong_seed);
    assert!(encryption::decrypt_from_group(&content, &nonce, &wrong_scalar, Some(1)).is_err());
}

// --- Phase 4: Wire format error paths ---

#[test]
fn decode_remark_empty_fails() {
    let empty = RemarkBytes::from_bytes(vec![]);
    assert!(decode_remark(&empty).is_err());
}

#[test]
fn decode_remark_invalid_version() {
    let bad = RemarkBytes::from_bytes(vec![0x20, 0x00]);
    assert!(decode_remark(&bad).is_err());
}

#[test]
fn is_samp_remark_false_for_non_samp() {
    assert!(!is_samp_remark(&[0x20, 0x00]));
}

#[test]
fn channel_create_round_trip() {
    let name = ChannelName::parse("mychan").unwrap();
    let desc = ChannelDescription::parse("a test channel").unwrap();
    let remark = encode_channel_create(&name, &desc);
    let Remark::ChannelCreate {
        name: n,
        description: d,
    } = decode_remark(&remark).unwrap()
    else {
        panic!("expected ChannelCreate");
    };
    assert_eq!(n.as_str(), "mychan");
    assert_eq!(d.as_str(), "a test channel");
}

#[test]
fn content_type_application_round_trip() {
    assert_eq!(ContentType::Application(0x18).to_byte(), 0x18);
    assert_eq!(ContentType::from_byte(0x18).unwrap(), ContentType::Application(0x18));
}

#[test]
fn decode_thread_content_truncated_fails() {
    assert!(decode_thread_content(&[0u8; 5]).is_err());
}

#[test]
fn decode_channel_content_truncated_fails() {
    assert!(decode_channel_content(&[0u8; 3]).is_err());
}
