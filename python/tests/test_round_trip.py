import os

import pytest
import samp_crypto

from samp import (
    Remark,
    SampError,
    decode_remark,
    decrypt,
    decrypt_from_group,
    encode_channel_msg,
    encode_encrypted,
    encode_group,
    encode_public,
    encrypt,
    encrypt_for_group,
)
from samp.encryption import compute_view_tag, decrypt_as_sender
from samp.wire import (
    CONTENT_TYPE_CHANNEL,
    CONTENT_TYPE_ENCRYPTED,
    CONTENT_TYPE_GROUP,
    CONTENT_TYPE_PUBLIC,
    CONTENT_TYPE_THREAD,
    decode_channel_content,
    decode_channel_create,
    decode_group_content,
    decode_group_members,
    decode_thread_content,
    encode_channel_content,
    encode_channel_create,
    encode_group_members,
    encode_thread_content,
)

SEED_A = bytes([0xAA] * 32)
SEED_B = bytes([0xBB] * 32)
SEED_C = bytes([0xCC] * 32)


def test_public_message_roundtrip():
    pub_b = samp_crypto.public_from_seed(SEED_B)
    body = b"Hello Bob!"
    remark = encode_public(pub_b, body)
    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_PUBLIC
    assert parsed.recipient == pub_b
    assert parsed.content == body


def test_encrypted_message_roundtrip():
    pub_b = samp_crypto.public_from_seed(SEED_B)
    scalar_b = samp_crypto.sr25519_signing_scalar(SEED_B)
    nonce = os.urandom(12)
    plaintext = b"secret message"

    encrypted_content = encrypt(plaintext, pub_b, nonce, SEED_A)
    view_tag = compute_view_tag(SEED_A, pub_b, nonce)
    remark = encode_encrypted(CONTENT_TYPE_ENCRYPTED, view_tag, nonce, encrypted_content)

    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_ENCRYPTED
    assert parsed.view_tag == view_tag
    assert parsed.nonce == nonce

    decrypted = decrypt(parsed.content, scalar_b, parsed.nonce)
    assert decrypted == plaintext


def test_encrypted_content_overhead():
    pub_b = samp_crypto.public_from_seed(SEED_B)
    nonce = os.urandom(12)
    content = encrypt(b"nine byte", pub_b, nonce, SEED_A)
    # ephemeral(32) + sealed_to(32) + plaintext(9) + auth_tag(16) = 89
    assert len(content) == 32 + 32 + 9 + 16


def test_sender_self_decryption():
    pub_b = samp_crypto.public_from_seed(SEED_B)
    nonce = os.urandom(12)
    plaintext = b"sender can read this too"
    encrypted_content = encrypt(plaintext, pub_b, nonce, SEED_A)
    decrypted = decrypt_as_sender(encrypted_content, SEED_A, nonce)
    assert decrypted == plaintext


def test_thread_content_roundtrip():
    thread = (100, 0)
    reply_to = (101, 1)
    continues = (99, 0)
    body = b"Hello in thread"
    content = encode_thread_content(thread, reply_to, continues, body)
    th, rt, ct, bd = decode_thread_content(content)
    assert th == thread
    assert rt == reply_to
    assert ct == continues
    assert bd == body


def test_channel_content_roundtrip():
    reply_to = (50, 1)
    continues = (49, 0)
    body = b"channel body"
    content = encode_channel_content(reply_to, continues, body)
    rt, ct, bd = decode_channel_content(content)
    assert rt == reply_to
    assert ct == continues
    assert bd == body


def test_channel_message_roundtrip():
    ch_ref = (100, 2)
    reply_to = (99, 1)
    continues = (98, 0)
    body = b"Did he use MEV shield?"
    remark = encode_channel_msg(ch_ref, reply_to, continues, body)
    assert remark[0] == CONTENT_TYPE_CHANNEL
    assert len(remark) == 19 + len(body)
    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_CHANNEL


def test_channel_create_roundtrip():
    content = encode_channel_create("general", "General discussion")
    assert content[0] == 0x13
    parsed = decode_remark(content)
    name, desc = decode_channel_create(parsed.content)
    assert name == "general"
    assert desc == "General discussion"


def test_reserved_content_type_rejected():
    try:
        decode_remark(bytes([0x15]))
        assert False, "should have raised"
    except SampError:
        pass


def test_non_samp_version_rejected():
    try:
        decode_remark(bytes([0x21]))
        assert False, "should have raised"
    except SampError:
        pass


def test_group_root_message_roundtrip():
    alice_pk = samp_crypto.public_from_seed(SEED_A)
    bob_pk = samp_crypto.public_from_seed(SEED_B)
    eve_pk = samp_crypto.public_from_seed(SEED_C)
    members = [alice_pk, bob_pk, eve_pk]

    nonce = bytes([0xAB] * 12)

    root_body = encode_group_members(members) + b"Welcome to the group!"

    zero_ref = (0, 0)
    plaintext = encode_thread_content(zero_ref, zero_ref, zero_ref, root_body)

    eph_pubkey, capsules, ciphertext = encrypt_for_group(plaintext, members, nonce, SEED_A)
    remark = encode_group(nonce, eph_pubkey, capsules, ciphertext)
    assert remark[0] == 0x15

    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_GROUP
    assert parsed.nonce == nonce

    bob_scalar = samp_crypto.sr25519_signing_scalar(SEED_B)
    decrypted = decrypt_from_group(parsed.content, bob_scalar, nonce, 3)
    group_ref, _reply_to, _continues, body = decode_group_content(decrypted)
    assert group_ref == (0, 0)
    member_list, first_msg = decode_group_members(body)
    assert len(member_list) == 3
    assert member_list[1] == bob_pk
    assert first_msg == b"Welcome to the group!"

    eve_scalar = samp_crypto.sr25519_signing_scalar(SEED_C)
    decrypted = decrypt_from_group(parsed.content, eve_scalar, nonce, 3)
    assert decrypted == plaintext

    alice_scalar = samp_crypto.sr25519_signing_scalar(SEED_A)
    decrypted = decrypt_from_group(parsed.content, alice_scalar, nonce, 3)
    assert decrypted == plaintext


def test_group_message_roundtrip():
    alice_pk = samp_crypto.public_from_seed(SEED_A)
    bob_pk = samp_crypto.public_from_seed(SEED_B)
    members = [alice_pk, bob_pk]

    nonce = bytes([0xCD] * 12)
    plaintext = encode_thread_content((100, 1), (99, 0), (0, 0), b"hello group")

    eph_pubkey, capsules, ciphertext = encrypt_for_group(plaintext, members, nonce, SEED_A)
    remark = encode_group(nonce, eph_pubkey, capsules, ciphertext)
    assert remark[0] == 0x15

    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_GROUP

    bob_scalar = samp_crypto.sr25519_signing_scalar(SEED_B)
    decrypted = decrypt_from_group(parsed.content, bob_scalar, nonce, 2)
    group_ref, reply_to, continues, body = decode_group_content(decrypted)
    assert group_ref == (100, 1)
    assert reply_to == (99, 0)
    assert continues == (0, 0)
    assert body == b"hello group"


def test_group_non_member_rejected():
    alice_pk = samp_crypto.public_from_seed(SEED_A)
    bob_pk = samp_crypto.public_from_seed(SEED_B)
    members = [alice_pk, bob_pk]

    nonce = bytes([0xCD] * 12)
    plaintext = encode_thread_content((100, 1), (99, 0), (0, 0), b"hello group")

    eph_pubkey, capsules, ciphertext = encrypt_for_group(plaintext, members, nonce, SEED_A)
    remark = encode_group(nonce, eph_pubkey, capsules, ciphertext)
    parsed = decode_remark(remark)

    eve_scalar = samp_crypto.sr25519_signing_scalar(SEED_C)
    try:
        decrypt_from_group(parsed.content, eve_scalar, nonce, 2)
        assert False, "should have raised"
    except Exception:
        pass


def test_encode_channel_create_name_too_long_returns_error():
    with pytest.raises(SampError):
        encode_channel_create("x" * 33, "desc")


def test_encode_channel_create_empty_name_returns_error():
    with pytest.raises(SampError):
        encode_channel_create("", "desc")


def test_encode_channel_create_desc_too_long_returns_error():
    with pytest.raises(SampError):
        encode_channel_create("valid", "x" * 129)


def test_group_trial_aead_without_known_n():
    alice_pk = samp_crypto.public_from_seed(SEED_A)
    bob_pk = samp_crypto.public_from_seed(SEED_B)
    eve_pk = samp_crypto.public_from_seed(SEED_C)
    members = [alice_pk, bob_pk, eve_pk]

    nonce = bytes([0xEF] * 12)
    plaintext = encode_thread_content((100, 1), (0, 0), (0, 0), b"trial test")

    eph_pubkey, capsules, ciphertext = encrypt_for_group(plaintext, members, nonce, SEED_A)
    remark = encode_group(nonce, eph_pubkey, capsules, ciphertext)
    parsed = decode_remark(remark)

    bob_scalar = samp_crypto.sr25519_signing_scalar(SEED_B)
    decrypted = decrypt_from_group(parsed.content, bob_scalar, nonce, None)
    group_ref, _reply_to, _continues, body = decode_group_content(decrypted)
    assert group_ref == (100, 1)
    assert body == b"trial test"

    eve_scalar = samp_crypto.sr25519_signing_scalar(SEED_C)
    decrypted = decrypt_from_group(parsed.content, eve_scalar, nonce, None)
    assert decrypted == plaintext

    alice_scalar = samp_crypto.sr25519_signing_scalar(SEED_A)
    decrypted = decrypt_from_group(parsed.content, alice_scalar, nonce, None)
    assert decrypted == plaintext
