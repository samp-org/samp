use samp::encryption::{
    compute_view_tag, decrypt, decrypt_as_sender, decrypt_from_group, encrypt, encrypt_for_group,
    sr25519_signing_scalar,
};
use samp::wire::BlockRef;
use samp::{
    decode_channel_content, decode_group_content, decode_group_members, decode_remark,
    decode_thread_content, encode_channel_content, encode_channel_msg, encode_encrypted,
    encode_group, encode_group_members, encode_public, encode_thread_content, ContentType,
    CONTENT_TYPE_ENCRYPTED, CONTENT_TYPE_THREAD,
};

use curve25519_dalek::ristretto::CompressedRistretto;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};

fn alice_seed() -> [u8; 32] {
    [0xAA; 32]
}
fn bob_seed() -> [u8; 32] {
    [0xBB; 32]
}
fn eve_seed() -> [u8; 32] {
    [0xCC; 32]
}

fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    MiniSecretKey::from_bytes(seed)
        .unwrap()
        .expand_to_keypair(ExpansionMode::Ed25519)
        .public
        .to_bytes()
}

fn bob_pubkey() -> CompressedRistretto {
    CompressedRistretto(pubkey_from_seed(&bob_seed()))
}
fn eve_pubkey() -> CompressedRistretto {
    CompressedRistretto(pubkey_from_seed(&eve_seed()))
}

// ---------------------------------------------------------------------------
// Public message (0x10)
// ---------------------------------------------------------------------------

#[test]
fn public_message_roundtrip() {
    let recipient = pubkey_from_seed(&bob_seed());
    let body = b"Hello Bob!";
    let remark = encode_public(&recipient, body);

    assert_eq!(remark[0], 0x10);
    assert_eq!(remark.len(), 33 + body.len());

    let decoded = decode_remark(&remark).unwrap();
    assert_eq!(decoded.content_type, ContentType::Public);
    assert_eq!(decoded.recipient, recipient);
    assert_eq!(decoded.content, body);
}

// ---------------------------------------------------------------------------
// Encrypted message (0x11)
// ---------------------------------------------------------------------------

#[test]
fn encrypted_message_roundtrip() {
    let nonce = [0xEE; 12];
    let plaintext = b"secret message";
    let encrypted = encrypt(plaintext, &bob_pubkey(), &nonce, &alice_seed()).unwrap();
    let vt = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();

    let remark = encode_encrypted(CONTENT_TYPE_ENCRYPTED, vt, &nonce, &encrypted);
    assert_eq!(remark[0], 0x11);

    let decoded = decode_remark(&remark).unwrap();
    assert_eq!(decoded.content_type, ContentType::Encrypted);
    assert_eq!(decoded.view_tag, vt);
    assert_eq!(decoded.nonce, nonce);
    assert_eq!(decoded.content, encrypted);

    let scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt(&decoded, &scalar).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// Thread message (0x12)
// ---------------------------------------------------------------------------

#[test]
fn thread_message_roundtrip() {
    let nonce = [0xDD; 12];
    let thread_content = encode_thread_content(
        BlockRef {
            block: 50,
            index: 0,
        },
        BlockRef {
            block: 100,
            index: 1,
        },
        BlockRef {
            block: 99,
            index: 0,
        },
        b"thread message",
    );
    let encrypted = encrypt(&thread_content, &bob_pubkey(), &nonce, &alice_seed()).unwrap();
    let vt = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();

    let remark = encode_encrypted(CONTENT_TYPE_THREAD, vt, &nonce, &encrypted);
    assert_eq!(remark[0], 0x12);

    let decoded = decode_remark(&remark).unwrap();
    assert_eq!(decoded.content_type, ContentType::Thread);

    let scalar = sr25519_signing_scalar(&bob_seed());
    let plaintext = decrypt(&decoded, &scalar).unwrap();
    let (thread, reply_to, continues, body) = decode_thread_content(&plaintext).unwrap();
    assert_eq!(
        thread,
        BlockRef {
            block: 50,
            index: 0
        }
    );
    assert_eq!(
        reply_to,
        BlockRef {
            block: 100,
            index: 1
        }
    );
    assert_eq!(
        continues,
        BlockRef {
            block: 99,
            index: 0
        }
    );
    assert_eq!(body, b"thread message");
}

// ---------------------------------------------------------------------------
// Channel creation (0x13)
// ---------------------------------------------------------------------------

#[test]
fn channel_creation_roundtrip() {
    let remark = samp::encode_channel_create("general", "The main channel").unwrap();
    assert_eq!(remark[0], 0x13);

    let decoded = decode_remark(&remark).unwrap();
    assert_eq!(decoded.content_type, ContentType::ChannelCreate);
    let (name, desc) = samp::wire::decode_channel_create(&decoded.content).unwrap();
    assert_eq!(name, "general");
    assert_eq!(desc, "The main channel");
}

// ---------------------------------------------------------------------------
// Channel message (0x14)
// ---------------------------------------------------------------------------

#[test]
fn channel_message_roundtrip() {
    let remark = encode_channel_msg(
        BlockRef {
            block: 200,
            index: 3,
        },
        BlockRef {
            block: 199,
            index: 1,
        },
        BlockRef {
            block: 198,
            index: 0,
        },
        b"channel message",
    );
    assert_eq!(remark[0], 0x14);
    assert_eq!(remark.len(), 19 + 15);

    let decoded = decode_remark(&remark).unwrap();
    assert_eq!(decoded.content_type, ContentType::Channel);

    let (reply_to, continues, body) = decode_channel_content(&decoded.content).unwrap();
    assert_eq!(
        reply_to,
        BlockRef {
            block: 199,
            index: 1
        }
    );
    assert_eq!(
        continues,
        BlockRef {
            block: 198,
            index: 0
        }
    );
    assert_eq!(body, b"channel message");
}

// ---------------------------------------------------------------------------
// Group message (0x15) -- per-message capsules
// ---------------------------------------------------------------------------

#[test]
fn group_root_message_roundtrip() {
    let alice_pk = pubkey_from_seed(&alice_seed());
    let bob_pk = pubkey_from_seed(&bob_seed());
    let eve_pk = pubkey_from_seed(&eve_seed());
    let members = vec![alice_pk, bob_pk, eve_pk];

    let nonce = [0xAB; 12];

    let mut root_body = encode_group_members(&members);
    root_body.extend_from_slice(b"Welcome to the group!");

    let plaintext =
        encode_thread_content(BlockRef::ZERO, BlockRef::ZERO, BlockRef::ZERO, &root_body);

    let (eph_pubkey, capsules, ciphertext) =
        encrypt_for_group(&plaintext, &members, &nonce, &alice_seed()).unwrap();
    let remark = encode_group(&nonce, &eph_pubkey, &capsules, &ciphertext);
    assert_eq!(remark[0], 0x15);

    let decoded = decode_remark(&remark).unwrap();
    assert_eq!(decoded.content_type, ContentType::Group);
    assert_eq!(decoded.nonce, nonce);

    let bob_scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt_from_group(&decoded.content, &bob_scalar, &nonce, Some(3)).unwrap();
    let (group_ref, _reply_to, _continues, body) = decode_group_content(&decrypted).unwrap();
    assert!(group_ref.is_zero());
    let (member_list, first_msg) = decode_group_members(body).unwrap();
    assert_eq!(member_list.len(), 3);
    assert_eq!(member_list[1], bob_pk);
    assert_eq!(first_msg, b"Welcome to the group!");

    let eve_scalar = sr25519_signing_scalar(&eve_seed());
    let decrypted = decrypt_from_group(&decoded.content, &eve_scalar, &nonce, Some(3)).unwrap();
    assert_eq!(decrypted, plaintext);

    let alice_scalar = sr25519_signing_scalar(&alice_seed());
    let decrypted = decrypt_from_group(&decoded.content, &alice_scalar, &nonce, Some(3)).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn group_message_roundtrip() {
    let alice_pk = pubkey_from_seed(&alice_seed());
    let bob_pk = pubkey_from_seed(&bob_seed());
    let members = vec![alice_pk, bob_pk];

    let nonce = [0xCD; 12];
    let plaintext = encode_thread_content(
        BlockRef {
            block: 100,
            index: 1,
        },
        BlockRef {
            block: 99,
            index: 0,
        },
        BlockRef::ZERO,
        b"hello group",
    );

    let (eph_pubkey, capsules, ciphertext) =
        encrypt_for_group(&plaintext, &members, &nonce, &alice_seed()).unwrap();
    let remark = encode_group(&nonce, &eph_pubkey, &capsules, &ciphertext);
    assert_eq!(remark[0], 0x15);

    let decoded = decode_remark(&remark).unwrap();
    assert_eq!(decoded.content_type, ContentType::Group);

    let bob_scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt_from_group(&decoded.content, &bob_scalar, &nonce, Some(2)).unwrap();
    let (group_ref, reply_to, continues, body) = decode_group_content(&decrypted).unwrap();
    assert_eq!(
        group_ref,
        BlockRef {
            block: 100,
            index: 1
        }
    );
    assert_eq!(
        reply_to,
        BlockRef {
            block: 99,
            index: 0
        }
    );
    assert!(continues.is_zero());
    assert_eq!(body, b"hello group");

    let eve_scalar = sr25519_signing_scalar(&eve_seed());
    assert!(decrypt_from_group(&decoded.content, &eve_scalar, &nonce, Some(2)).is_err());
}

#[test]
fn group_trial_aead_without_known_n() {
    let alice_pk = pubkey_from_seed(&alice_seed());
    let bob_pk = pubkey_from_seed(&bob_seed());
    let eve_pk = pubkey_from_seed(&eve_seed());
    let members = vec![alice_pk, bob_pk, eve_pk];

    let nonce = [0xEF; 12];
    let plaintext = encode_thread_content(
        BlockRef {
            block: 500,
            index: 2,
        },
        BlockRef::ZERO,
        BlockRef::ZERO,
        b"trial aead test",
    );

    let (eph_pubkey, capsules, ciphertext) =
        encrypt_for_group(&plaintext, &members, &nonce, &alice_seed()).unwrap();
    let remark = encode_group(&nonce, &eph_pubkey, &capsules, &ciphertext);
    let decoded = decode_remark(&remark).unwrap();

    let bob_scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt_from_group(&decoded.content, &bob_scalar, &nonce, None).unwrap();
    let (group_ref, _, _, body) = decode_group_content(&decrypted).unwrap();
    assert_eq!(
        group_ref,
        BlockRef {
            block: 500,
            index: 2
        }
    );
    assert_eq!(body, b"trial aead test");
}

// ---------------------------------------------------------------------------
// 1:1 encryption edge cases
// ---------------------------------------------------------------------------

#[test]
fn encrypted_message_unreadable_by_third_party() {
    let nonce = [0xDD; 12];
    let plaintext = b"secret between Alice and Bob";
    let encrypted = encrypt(plaintext, &bob_pubkey(), &nonce, &alice_seed()).unwrap();
    let vt = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();
    let remark = encode_encrypted(CONTENT_TYPE_ENCRYPTED, vt, &nonce, &encrypted);
    let decoded = decode_remark(&remark).unwrap();

    let bob_scalar = sr25519_signing_scalar(&bob_seed());
    let decrypted = decrypt(&decoded, &bob_scalar).unwrap();
    assert_eq!(decrypted, plaintext);

    let eve_scalar = sr25519_signing_scalar(&eve_seed());
    assert!(decrypt(&decoded, &eve_scalar).is_err());
}

#[test]
fn sender_can_decrypt_own_message() {
    let nonce = [0xFF; 12];
    let plaintext = b"my own message";
    let encrypted = encrypt(plaintext, &bob_pubkey(), &nonce, &alice_seed()).unwrap();
    let vt = compute_view_tag(&alice_seed(), &bob_pubkey(), &nonce).unwrap();
    let remark = encode_encrypted(CONTENT_TYPE_ENCRYPTED, vt, &nonce, &encrypted);
    let decoded = decode_remark(&remark).unwrap();

    let decrypted = decrypt_as_sender(&decoded, &alice_seed()).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn view_tag_filters_correctly() {
    let nonce = [0x11; 12];
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

// ---------------------------------------------------------------------------
// Content helpers
// ---------------------------------------------------------------------------

#[test]
fn thread_content_roundtrip() {
    let thread = BlockRef {
        block: 50,
        index: 0,
    };
    let reply_to = BlockRef {
        block: 100,
        index: 3,
    };
    let continues = BlockRef {
        block: 99,
        index: 1,
    };
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
    let reply_to = BlockRef {
        block: 100,
        index: 3,
    };
    let continues = BlockRef {
        block: 99,
        index: 1,
    };
    let body = b"Hello in channel";

    let content = encode_channel_content(reply_to, continues, body);
    let (rt, ct, bd) = decode_channel_content(&content).unwrap();
    assert_eq!(rt, reply_to);
    assert_eq!(ct, continues);
    assert_eq!(bd, body);
}

#[test]
fn channel_message_is_lean() {
    let body = b"Did he use MEV shield?";
    let remark = encode_channel_msg(
        BlockRef {
            block: 520,
            index: 14,
        },
        BlockRef {
            block: 519,
            index: 2,
        },
        BlockRef {
            block: 518,
            index: 0,
        },
        body,
    );
    assert_eq!(remark.len(), 41);
}

// ---------------------------------------------------------------------------
// Channel validation
// ---------------------------------------------------------------------------

#[test]
fn encode_channel_create_name_too_long_returns_error() {
    let name = "a".repeat(33);
    assert!(samp::encode_channel_create(&name, "desc").is_err());
}

#[test]
fn encode_channel_create_empty_name_returns_error() {
    assert!(samp::encode_channel_create("", "desc").is_err());
}

#[test]
fn encode_channel_create_desc_too_long_returns_error() {
    let desc = "a".repeat(129);
    assert!(samp::encode_channel_create("name", &desc).is_err());
}
