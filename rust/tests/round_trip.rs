use samp::encryption::{
    compute_view_tag, decrypt, decrypt_as_sender, decrypt_from_group, encrypt, encrypt_for_group,
    sr25519_signing_scalar,
};
use samp::{
    decode_channel_content, decode_group_content, decode_group_members, decode_remark,
    decode_thread_content, encode_channel_content, encode_channel_msg, encode_encrypted,
    encode_group, encode_group_members, encode_public, encode_thread_content, BlockRef,
    ChannelDescription, ChannelName, ContentType, Nonce, Plaintext, Pubkey, Remark, Seed,
};

use schnorrkel::keys::{ExpansionMode, MiniSecretKey};

fn pt(b: &[u8]) -> Plaintext {
    Plaintext::from_bytes(b.to_vec())
}

fn cn(s: &str) -> ChannelName {
    ChannelName::parse(s.to_string()).expect("valid channel name")
}

fn cd(s: &str) -> ChannelDescription {
    ChannelDescription::parse(s.to_string()).expect("valid channel description")
}

fn alice_seed() -> Seed {
    Seed::from_bytes([0xAA; 32])
}
fn bob_seed() -> Seed {
    Seed::from_bytes([0xBB; 32])
}
fn eve_seed() -> Seed {
    Seed::from_bytes([0xCC; 32])
}

fn pubkey_from_seed(seed: &Seed) -> Pubkey {
    Pubkey::from_bytes(
        MiniSecretKey::from_bytes(seed.expose_secret())
            .unwrap()
            .expand_to_keypair(ExpansionMode::Ed25519)
            .public
            .to_bytes(),
    )
}

fn bob_pubkey() -> Pubkey {
    pubkey_from_seed(&bob_seed())
}
fn eve_pubkey() -> Pubkey {
    pubkey_from_seed(&eve_seed())
}

fn br(b: u32, i: u16) -> BlockRef {
    BlockRef::from_parts(b, i)
}

fn n(b: u8) -> Nonce {
    Nonce::from_bytes([b; 12])
}

// Public message (0x10)

#[test]
fn public_message_roundtrip() {
    let recipient = pubkey_from_seed(&bob_seed());
    let body = "Hello Bob!";
    let remark = encode_public(&recipient, body);

    assert_eq!(remark.as_bytes()[0], 0x10);
    assert_eq!(remark.len(), 33 + body.len());

    let Remark::Public { recipient: r, body: b } = decode_remark(&remark).unwrap() else {
        panic!("expected Public");
    };
    assert_eq!(r, recipient);
    assert_eq!(b, body);
}

// Encrypted message (0x11)

#[test]
fn encrypted_message_roundtrip() {
    let nonce = n(0xEE);
    let plaintext = pt(b"secret message");
    let encrypted = encrypt(&plaintext, &bob_pubkey(), &nonce, &alice_seed()).unwrap();
    let vt = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();

    let remark = encode_encrypted(ContentType::Encrypted, vt, &nonce, &encrypted);
    assert_eq!(remark.as_bytes()[0], 0x11);

    let Remark::Encrypted(payload) = decode_remark(&remark).unwrap() else {
        panic!("expected Encrypted");
    };
    assert_eq!(payload.view_tag, vt);
    assert_eq!(payload.nonce, nonce);
    assert_eq!(payload.encrypted_content, encrypted);

    let scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt(&payload, &scalar).unwrap();
    assert_eq!(decrypted, plaintext);
}

// Thread message (0x12)

#[test]
fn thread_message_roundtrip() {
    let nonce = n(0xDD);
    let thread_content = encode_thread_content(
        br(50, 0),
        br(100, 1),
        br(99, 0),
        b"thread message",
    );
    let encrypted = encrypt(&pt(&thread_content), &bob_pubkey(), &nonce, &alice_seed()).unwrap();
    let vt = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();

    let remark = encode_encrypted(ContentType::Thread, vt, &nonce, &encrypted);
    assert_eq!(remark.as_bytes()[0], 0x12);

    let Remark::Thread(payload) = decode_remark(&remark).unwrap() else {
        panic!("expected Thread");
    };

    let scalar = sr25519_signing_scalar(&bob_seed());
    let plaintext = decrypt(&payload, &scalar).unwrap();
    let (thread, reply_to, continues, body) = decode_thread_content(plaintext.as_bytes()).unwrap();
    assert_eq!(
        thread,
        br(50, 0)
    );
    assert_eq!(
        reply_to,
        br(100, 1)
    );
    assert_eq!(
        continues,
        br(99, 0)
    );
    assert_eq!(body, b"thread message");
}

// Channel creation (0x13)

#[test]
fn channel_creation_roundtrip() {
    let remark = samp::encode_channel_create(&cn("general"), &cd("The main channel"));
    assert_eq!(remark.as_bytes()[0], 0x13);

    let Remark::ChannelCreate { name, description } = decode_remark(&remark).unwrap() else {
        panic!("expected ChannelCreate");
    };
    assert_eq!(name.as_str(), "general");
    assert_eq!(description.as_str(), "The main channel");
}

// Channel message (0x14)

#[test]
fn channel_message_roundtrip() {
    let remark = encode_channel_msg(
        br(200, 3),
        br(199, 1),
        br(198, 0),
        "channel message",
    );
    assert_eq!(remark.as_bytes()[0], 0x14);
    assert_eq!(remark.len(), 19 + 15);

    let Remark::Channel { channel_ref, content } = decode_remark(&remark).unwrap() else {
        panic!("expected Channel");
    };
    assert_eq!(channel_ref, br(200, 3));

    let (reply_to, continues, body) = decode_channel_content(&content).unwrap();
    assert_eq!(
        reply_to,
        br(199, 1)
    );
    assert_eq!(
        continues,
        br(198, 0)
    );
    assert_eq!(body, b"channel message");
}

// Group message (0x15) -- per-message capsules

#[test]
fn group_root_message_roundtrip() {
    let alice_pk = pubkey_from_seed(&alice_seed());
    let bob_pk = pubkey_from_seed(&bob_seed());
    let eve_pk = pubkey_from_seed(&eve_seed());
    let members = vec![alice_pk, bob_pk, eve_pk];

    let nonce = n(0xAB);

    let mut root_body = encode_group_members(&members);
    root_body.extend_from_slice(b"Welcome to the group!");

    let plaintext = pt(&encode_thread_content(
        BlockRef::ZERO,
        BlockRef::ZERO,
        BlockRef::ZERO,
        &root_body,
    ));

    let (eph_pubkey, capsules, ciphertext) =
        encrypt_for_group(&plaintext, &members, &nonce, &alice_seed()).unwrap();
    let remark = encode_group(&nonce, &eph_pubkey, &capsules, &ciphertext);
    assert_eq!(remark.as_bytes()[0], 0x15);

    let Remark::Group(payload) = decode_remark(&remark).unwrap() else {
        panic!("expected Group");
    };
    assert_eq!(payload.nonce, nonce);

    let bob_scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt_from_group(&payload, &bob_scalar, Some(3)).unwrap();
    let (group_ref, _reply_to, _continues, body) =
        decode_group_content(decrypted.as_bytes()).unwrap();
    assert!(group_ref.is_zero());
    let (member_list, first_msg) = decode_group_members(body).unwrap();
    assert_eq!(member_list.len(), 3);
    assert_eq!(member_list[1], bob_pk);
    assert_eq!(first_msg, b"Welcome to the group!");

    let eve_scalar = sr25519_signing_scalar(&eve_seed());
    let decrypted = decrypt_from_group(&payload, &eve_scalar, Some(3)).unwrap();
    assert_eq!(decrypted, plaintext);

    let alice_scalar = sr25519_signing_scalar(&alice_seed());
    let decrypted = decrypt_from_group(&payload, &alice_scalar, Some(3)).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn group_message_roundtrip() {
    let alice_pk = pubkey_from_seed(&alice_seed());
    let bob_pk = pubkey_from_seed(&bob_seed());
    let members = vec![alice_pk, bob_pk];

    let nonce = n(0xCD);
    let plaintext = pt(&encode_thread_content(
        br(100, 1),
        br(99, 0),
        BlockRef::ZERO,
        b"hello group",
    ));

    let (eph_pubkey, capsules, ciphertext) =
        encrypt_for_group(&plaintext, &members, &nonce, &alice_seed()).unwrap();
    let remark = encode_group(&nonce, &eph_pubkey, &capsules, &ciphertext);
    assert_eq!(remark.as_bytes()[0], 0x15);

    let Remark::Group(payload) = decode_remark(&remark).unwrap() else {
        panic!("expected Group");
    };

    let bob_scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt_from_group(&payload, &bob_scalar, Some(2)).unwrap();
    let (group_ref, reply_to, continues, body) =
        decode_group_content(decrypted.as_bytes()).unwrap();
    assert_eq!(
        group_ref,
        br(100, 1)
    );
    assert_eq!(
        reply_to,
        br(99, 0)
    );
    assert!(continues.is_zero());
    assert_eq!(body, b"hello group");

    let eve_scalar = sr25519_signing_scalar(&eve_seed());
    assert!(decrypt_from_group(&payload, &eve_scalar, Some(2)).is_err());
}

#[test]
fn group_trial_aead_without_known_n() {
    let alice_pk = pubkey_from_seed(&alice_seed());
    let bob_pk = pubkey_from_seed(&bob_seed());
    let eve_pk = pubkey_from_seed(&eve_seed());
    let members = vec![alice_pk, bob_pk, eve_pk];

    let nonce = n(0xEF);
    let plaintext = pt(&encode_thread_content(
        br(500, 2),
        BlockRef::ZERO,
        BlockRef::ZERO,
        b"trial aead test",
    ));

    let (eph_pubkey, capsules, ciphertext) =
        encrypt_for_group(&plaintext, &members, &nonce, &alice_seed()).unwrap();
    let remark = encode_group(&nonce, &eph_pubkey, &capsules, &ciphertext);
    let Remark::Group(payload) = decode_remark(&remark).unwrap() else {
        panic!("expected Group");
    };

    let bob_scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt_from_group(&payload, &bob_scalar, None).unwrap();
    let (group_ref, _, _, body) = decode_group_content(decrypted.as_bytes()).unwrap();
    assert_eq!(
        group_ref,
        br(500, 2)
    );
    assert_eq!(body, b"trial aead test");
}

// 1:1 encryption edge cases

#[test]
fn encrypted_message_unreadable_by_third_party() {
    let nonce = n(0xDD);
    let plaintext = pt(b"secret between Alice and Bob");
    let encrypted = encrypt(&plaintext, &bob_pubkey(), &nonce, &alice_seed()).unwrap();
    let vt = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();
    let remark = encode_encrypted(ContentType::Encrypted, vt, &nonce, &encrypted);
    let Remark::Encrypted(payload) = decode_remark(&remark).unwrap() else {
        panic!("expected Encrypted");
    };

    let bob_scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt(&payload, &bob_scalar).unwrap();
    assert_eq!(decrypted, plaintext);

    let eve_scalar = sr25519_signing_scalar(&eve_seed());
    assert!(decrypt(&payload, &eve_scalar).is_err());
}

#[test]
fn sender_can_decrypt_own_message() {
    let nonce = n(0xFF);
    let plaintext = pt(b"my own message");
    let encrypted = encrypt(&plaintext, &bob_pubkey(), &nonce, &alice_seed()).unwrap();
    let vt = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();
    let remark = encode_encrypted(ContentType::Encrypted, vt, &nonce, &encrypted);
    let Remark::Encrypted(payload) = decode_remark(&remark).unwrap() else {
        panic!("expected Encrypted");
    };

    let decrypted = decrypt_as_sender(&payload, &alice_seed()).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn view_tag_filters_correctly() {
    let nonce = n(0x11);
    let sender_tag = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();
    let eve_tag = compute_view_tag(&alice_seed(), &eve_pubkey(), &nonce).unwrap();
    if eve_tag == sender_tag {
        eprintln!("Warning: eve_tag == sender_tag (1/256 chance)");
    }
}

#[test]
fn content_type_reserved_rejected() {
    assert!(ContentType::from_byte(0x16).is_err());
    assert!(ContentType::from_byte(0x17).is_err());
}

// Content helpers

#[test]
fn thread_content_roundtrip() {
    let thread = br(50, 0);
    let reply_to = br(100, 3);
    let continues = br(99, 1);
    let body = b"Hello in thread";

    let content = encode_thread_content(thread, reply_to, continues, body);
    let (th, rt, ct, bd) = decode_thread_content(&content).unwrap();
    assert_eq!(th, thread);
    assert_eq!(rt, reply_to);
    assert_eq!(ct, continues);
    assert_eq!(bd, body);
}

#[test]
fn channel_content_roundtrip() {
    let reply_to = br(100, 3);
    let continues = br(99, 1);
    let body = b"Hello in channel";

    let content = encode_channel_content(reply_to, continues, body);
    let (rt, ct, bd) = decode_channel_content(&content).unwrap();
    assert_eq!(rt, reply_to);
    assert_eq!(ct, continues);
    assert_eq!(bd, body);
}

#[test]
fn channel_message_is_lean() {
    let body = "Did he use MEV shield?";
    let remark = encode_channel_msg(
        br(520, 14),
        br(519, 2),
        br(518, 0),
        body,
    );
    assert_eq!(remark.len(), 41);
}

// Channel validation

#[test]
fn channel_name_too_long_returns_error() {
    assert!(ChannelName::parse("a".repeat(33)).is_err());
}

#[test]
fn channel_name_empty_returns_error() {
    assert!(ChannelName::parse("").is_err());
}

#[test]
fn channel_description_too_long_returns_error() {
    assert!(ChannelDescription::parse("a".repeat(129)).is_err());
}
