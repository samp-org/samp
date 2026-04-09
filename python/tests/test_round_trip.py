from __future__ import annotations

import os

import pytest
import samp_crypto  # type: ignore[import-not-found]

from samp import (
    BlockRef,
    ChannelCreateRemark,
    ChannelDescription,
    ChannelName,
    ChannelRemark,
    ContentType,
    EncryptedRemark,
    GroupRemark,
    PublicRemark,
    SampError,
    Seed,
    block_number_from_int,
    decode_remark,
    decrypt,
    decrypt_from_group,
    encode_channel_msg,
    encode_encrypted,
    encode_group,
    encode_public,
    encrypt,
    encrypt_for_group,
    ext_index_from_int,
    nonce_from_bytes,
    plaintext_from_bytes,
    pubkey_from_bytes,
    sr25519_signing_scalar,
)
from samp.encryption import compute_view_tag, decrypt_as_sender
from samp.wire import (
    decode_channel_content,
    decode_group_content,
    decode_group_members,
    decode_thread_content,
    encode_channel_content,
    encode_channel_create,
    encode_group_members,
    encode_thread_content,
)

SEED_A = Seed.from_bytes(bytes([0xAA] * 32))
SEED_B = Seed.from_bytes(bytes([0xBB] * 32))
SEED_C = Seed.from_bytes(bytes([0xCC] * 32))


def _br(n: int, i: int) -> BlockRef:
    return BlockRef.of(block_number_from_int(n), ext_index_from_int(i))


def _pk(seed: Seed) -> "bytes":
    return samp_crypto.public_from_seed(seed.expose_secret())  # type: ignore[no-any-return]


def test_public_message_roundtrip() -> None:
    pub_b = pubkey_from_bytes(_pk(SEED_B))
    body = "Hello Bob!"
    remark = encode_public(pub_b, body)
    assert remark[0] == ContentType.PUBLIC
    parsed = decode_remark(remark)
    assert isinstance(parsed, PublicRemark)
    assert parsed.recipient == pub_b
    assert parsed.body == body


def test_encrypted_message_roundtrip() -> None:
    pub_b = pubkey_from_bytes(_pk(SEED_B))
    scalar_b = sr25519_signing_scalar(SEED_B)
    nonce = nonce_from_bytes(os.urandom(12))
    plaintext = plaintext_from_bytes(b"secret message")

    ciphertext = encrypt(plaintext, pub_b, nonce, SEED_A)
    view_tag = compute_view_tag(SEED_A, pub_b, nonce)
    remark = encode_encrypted(ContentType.ENCRYPTED, view_tag, nonce, ciphertext)

    parsed = decode_remark(remark)
    assert isinstance(parsed, EncryptedRemark)
    assert parsed.view_tag == view_tag
    assert parsed.nonce == nonce

    decrypted = decrypt(parsed.ciphertext, parsed.nonce, scalar_b)
    assert decrypted == plaintext


def test_non_samp_version_rejected() -> None:
    with pytest.raises(SampError):
        decode_remark(bytes([0x21, 0x00]))


def test_encrypted_content_overhead() -> None:
    pub_b = pubkey_from_bytes(_pk(SEED_B))
    nonce = nonce_from_bytes(os.urandom(12))
    content = encrypt(plaintext_from_bytes(b"nine byte"), pub_b, nonce, SEED_A)
    assert len(content) == 32 + 32 + 9 + 16


def test_sender_self_decryption() -> None:
    pub_b = pubkey_from_bytes(_pk(SEED_B))
    nonce = nonce_from_bytes(os.urandom(12))
    plaintext = plaintext_from_bytes(b"sender can read this too")
    encrypted = encrypt(plaintext, pub_b, nonce, SEED_A)
    view_tag = compute_view_tag(SEED_A, pub_b, nonce)
    remark = encode_encrypted(ContentType.ENCRYPTED, view_tag, nonce, encrypted)
    parsed = decode_remark(remark)
    assert isinstance(parsed, EncryptedRemark)
    decrypted = decrypt_as_sender(parsed.ciphertext, parsed.nonce, SEED_A)
    assert decrypted == plaintext


def test_thread_content_roundtrip() -> None:
    thread = _br(100, 0)
    reply_to = _br(101, 1)
    continues = _br(99, 0)
    body = b"Hello in thread"
    content = encode_thread_content(thread, reply_to, continues, body)
    th, rt, ct, bd = decode_thread_content(content)
    assert th == thread
    assert rt == reply_to
    assert ct == continues
    assert bd == body


def test_channel_content_roundtrip() -> None:
    reply_to = _br(50, 1)
    continues = _br(49, 0)
    body = b"channel body"
    content = encode_channel_content(reply_to, continues, body)
    rt, ct, bd = decode_channel_content(content)
    assert rt == reply_to
    assert ct == continues
    assert bd == body


def test_channel_message_roundtrip() -> None:
    ch_ref = _br(100, 2)
    reply_to = _br(99, 1)
    continues = _br(98, 0)
    body = "Did he use MEV shield?"
    remark = encode_channel_msg(ch_ref, reply_to, continues, body)
    assert remark[0] == ContentType.CHANNEL
    assert len(remark) == 19 + len(body.encode("utf-8"))
    parsed = decode_remark(remark)
    assert isinstance(parsed, ChannelRemark)
    assert parsed.channel_ref == ch_ref
    assert parsed.body == body


def test_channel_create_roundtrip() -> None:
    content = encode_channel_create(
        ChannelName.parse("general"),
        ChannelDescription.parse("General discussion"),
    )
    assert content[0] == 0x13
    parsed = decode_remark(content)
    assert isinstance(parsed, ChannelCreateRemark)
    assert parsed.name.as_str() == "general"
    assert parsed.description.as_str() == "General discussion"


def test_reserved_content_type_rejected() -> None:
    with pytest.raises(SampError):
        decode_remark(bytes([0x16]))
    with pytest.raises(SampError):
        decode_remark(bytes([0x17]))


def test_group_root_message_roundtrip() -> None:
    alice_pk = pubkey_from_bytes(_pk(SEED_A))
    bob_pk = pubkey_from_bytes(_pk(SEED_B))
    eve_pk = pubkey_from_bytes(_pk(SEED_C))
    members = [alice_pk, bob_pk, eve_pk]

    nonce = nonce_from_bytes(bytes([0xAB] * 12))

    root_body = encode_group_members(members) + b"Welcome to the group!"

    zero_ref = BlockRef.zero()
    plaintext = plaintext_from_bytes(
        encode_thread_content(zero_ref, zero_ref, zero_ref, root_body)
    )

    eph_pubkey, capsules, ciphertext = encrypt_for_group(plaintext, members, nonce, SEED_A)
    remark = encode_group(nonce, eph_pubkey, capsules, ciphertext)
    assert remark[0] == 0x15

    parsed = decode_remark(remark)
    assert isinstance(parsed, GroupRemark)
    assert parsed.nonce == nonce

    bob_scalar = sr25519_signing_scalar(SEED_B)
    decrypted = decrypt_from_group(parsed.content, bob_scalar, nonce, 3)
    group_ref, _reply_to, _continues, body = decode_group_content(decrypted)
    assert group_ref == zero_ref
    member_list, first_msg = decode_group_members(body)
    assert len(member_list) == 3
    assert member_list[1] == bob_pk
    assert first_msg == b"Welcome to the group!"

    eve_scalar = sr25519_signing_scalar(SEED_C)
    decrypted = decrypt_from_group(parsed.content, eve_scalar, nonce, 3)
    assert decrypted == plaintext

    alice_scalar = sr25519_signing_scalar(SEED_A)
    decrypted = decrypt_from_group(parsed.content, alice_scalar, nonce, 3)
    assert decrypted == plaintext


def test_group_message_roundtrip() -> None:
    alice_pk = pubkey_from_bytes(_pk(SEED_A))
    bob_pk = pubkey_from_bytes(_pk(SEED_B))
    members = [alice_pk, bob_pk]

    nonce = nonce_from_bytes(bytes([0xCD] * 12))
    plaintext = plaintext_from_bytes(
        encode_thread_content(_br(100, 1), _br(99, 0), BlockRef.zero(), b"hello group")
    )

    eph_pubkey, capsules, ciphertext = encrypt_for_group(plaintext, members, nonce, SEED_A)
    remark = encode_group(nonce, eph_pubkey, capsules, ciphertext)
    assert remark[0] == 0x15

    parsed = decode_remark(remark)
    assert isinstance(parsed, GroupRemark)

    bob_scalar = sr25519_signing_scalar(SEED_B)
    decrypted = decrypt_from_group(parsed.content, bob_scalar, nonce, 2)
    group_ref, reply_to, continues, body = decode_group_content(decrypted)
    assert group_ref == _br(100, 1)
    assert reply_to == _br(99, 0)
    assert continues == BlockRef.zero()
    assert body == b"hello group"


def test_group_non_member_rejected() -> None:
    alice_pk = pubkey_from_bytes(_pk(SEED_A))
    bob_pk = pubkey_from_bytes(_pk(SEED_B))
    members = [alice_pk, bob_pk]

    nonce = nonce_from_bytes(bytes([0xCD] * 12))
    plaintext = plaintext_from_bytes(
        encode_thread_content(_br(100, 1), _br(99, 0), BlockRef.zero(), b"hello group")
    )

    eph_pubkey, capsules, ciphertext = encrypt_for_group(plaintext, members, nonce, SEED_A)
    remark = encode_group(nonce, eph_pubkey, capsules, ciphertext)
    parsed = decode_remark(remark)
    assert isinstance(parsed, GroupRemark)

    eve_scalar = sr25519_signing_scalar(SEED_C)
    with pytest.raises(Exception):
        decrypt_from_group(parsed.content, eve_scalar, nonce, 2)


def test_encode_channel_create_name_too_long_returns_error() -> None:
    with pytest.raises(SampError):
        ChannelName.parse("x" * 33)


def test_encode_channel_create_empty_name_returns_error() -> None:
    with pytest.raises(SampError):
        ChannelName.parse("")


def test_encode_channel_create_desc_too_long_returns_error() -> None:
    with pytest.raises(SampError):
        ChannelDescription.parse("x" * 129)


def test_group_trial_aead_without_known_n() -> None:
    alice_pk = pubkey_from_bytes(_pk(SEED_A))
    bob_pk = pubkey_from_bytes(_pk(SEED_B))
    eve_pk = pubkey_from_bytes(_pk(SEED_C))
    members = [alice_pk, bob_pk, eve_pk]

    nonce = nonce_from_bytes(bytes([0xEF] * 12))
    plaintext = plaintext_from_bytes(
        encode_thread_content(_br(100, 1), BlockRef.zero(), BlockRef.zero(), b"trial test")
    )

    eph_pubkey, capsules, ciphertext = encrypt_for_group(plaintext, members, nonce, SEED_A)
    remark = encode_group(nonce, eph_pubkey, capsules, ciphertext)
    parsed = decode_remark(remark)
    assert isinstance(parsed, GroupRemark)

    bob_scalar = sr25519_signing_scalar(SEED_B)
    decrypted = decrypt_from_group(parsed.content, bob_scalar, nonce, None)
    group_ref, _reply_to, _continues, body = decode_group_content(decrypted)
    assert group_ref == _br(100, 1)
    assert body == b"trial test"

    eve_scalar = sr25519_signing_scalar(SEED_C)
    decrypted = decrypt_from_group(parsed.content, eve_scalar, nonce, None)
    assert decrypted == plaintext

    alice_scalar = sr25519_signing_scalar(SEED_A)
    decrypted = decrypt_from_group(parsed.content, alice_scalar, nonce, None)
    assert decrypted == plaintext
