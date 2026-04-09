from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from samp import (
    BlockRef,
    ChannelCreateRemark,
    ChannelDescription,
    ChannelName,
    ChannelRemark,
    EncryptedRemark,
    GroupRemark,
    PublicRemark,
    SampError,
    Seed,
    block_number_from_int,
    decode_remark,
    encrypt,
    ext_index_from_int,
    nonce_from_bytes,
    plaintext_from_bytes,
    pubkey_from_bytes,
    sr25519_signing_scalar,
)
from samp.encryption import compute_view_tag, decrypt, decrypt_as_sender, decrypt_from_group
from samp.wire import (
    ContentType,
    decode_channel_create,
    decode_thread_content,
    encode_channel_create,
    encode_channel_msg,
    encode_encrypted,
    encode_group_members,
    encode_public,
    encode_thread_content,
)

VECTORS_PATH = Path(__file__).resolve().parent.parent.parent / "e2e" / "test-vectors.json"


def load_vectors() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(VECTORS_PATH.read_text())
    return data


def h(s: str) -> bytes:
    return bytes.fromhex(s.removeprefix("0x"))


def _br(pair: list[int]) -> BlockRef:
    return BlockRef.of(block_number_from_int(pair[0]), ext_index_from_int(pair[1]))


def test_keypair_alice() -> None:
    import samp_crypto  # type: ignore[import-not-found]

    v = load_vectors()
    seed_bytes = h(v["alice"]["seed"])
    seed = Seed.from_bytes(seed_bytes)
    pub = samp_crypto.public_from_seed(seed.expose_secret())
    assert pub == h(v["alice"]["sr25519_public"])
    scalar = sr25519_signing_scalar(seed)
    assert scalar == h(v["alice"]["signing_scalar"])


def test_keypair_bob() -> None:
    import samp_crypto  # type: ignore[import-not-found]

    v = load_vectors()
    seed_bytes = h(v["bob"]["seed"])
    seed = Seed.from_bytes(seed_bytes)
    pub = samp_crypto.public_from_seed(seed.expose_secret())
    assert pub == h(v["bob"]["sr25519_public"])
    scalar = sr25519_signing_scalar(seed)
    assert scalar == h(v["bob"]["signing_scalar"])


def test_public_message_encoding() -> None:
    v = load_vectors()
    bob_pub = pubkey_from_bytes(h(v["bob"]["sr25519_public"]))
    body_bytes = h(v["public_message"]["body"])
    body = body_bytes.decode("utf-8")
    remark = encode_public(bob_pub, body)
    assert remark == h(v["public_message"]["remark"])


def test_public_message_decoding() -> None:
    v = load_vectors()
    remark = h(v["public_message"]["remark"])
    parsed = decode_remark(remark)
    assert isinstance(parsed, PublicRemark)
    assert parsed.body.encode("utf-8") == h(v["public_message"]["body"])


def test_encrypted_message_encoding() -> None:
    v = load_vectors()
    alice_seed = Seed.from_bytes(h(v["alice"]["seed"]))
    bob_pub = pubkey_from_bytes(h(v["bob"]["sr25519_public"]))
    nonce = nonce_from_bytes(h(v["encrypted_message"]["nonce"]))
    plaintext = plaintext_from_bytes(h(v["encrypted_message"]["plaintext"]))

    ciphertext = encrypt(plaintext, bob_pub, nonce, alice_seed)
    assert ciphertext == h(v["encrypted_message"]["encrypted_content"])

    view_tag = compute_view_tag(alice_seed, bob_pub, nonce)
    assert view_tag == v["encrypted_message"]["view_tag"]

    remark = encode_encrypted(ContentType.ENCRYPTED, view_tag, nonce, ciphertext)
    assert remark == h(v["encrypted_message"]["remark"])


def test_encrypted_message_intermediates() -> None:
    v = load_vectors()
    content = h(v["encrypted_message"]["encrypted_content"])
    assert content[:32] == h(v["encrypted_message"]["ephemeral_pubkey"])
    assert content[32:64] == h(v["encrypted_message"]["sealed_to"])
    assert content[64:] == h(v["encrypted_message"]["ciphertext_with_tag"])


def test_encrypted_message_decoding() -> None:
    v = load_vectors()
    remark = h(v["encrypted_message"]["remark"])
    parsed = decode_remark(remark)
    assert isinstance(parsed, EncryptedRemark)
    assert parsed.view_tag == v["encrypted_message"]["view_tag"]
    assert parsed.nonce == h(v["encrypted_message"]["nonce"])


def test_encrypted_recipient_decryption() -> None:
    v = load_vectors()
    bob_seed = Seed.from_bytes(h(v["bob"]["seed"]))
    bob_scalar = sr25519_signing_scalar(bob_seed)
    parsed = decode_remark(h(v["encrypted_message"]["remark"]))
    assert isinstance(parsed, EncryptedRemark)
    plaintext = decrypt(parsed.ciphertext, parsed.nonce, bob_scalar)
    assert plaintext == h(v["encrypted_message"]["plaintext"])


def test_sender_self_decryption() -> None:
    v = load_vectors()
    alice_seed = Seed.from_bytes(h(v["alice"]["seed"]))
    parsed = decode_remark(h(v["encrypted_message"]["remark"]))
    assert isinstance(parsed, EncryptedRemark)
    plaintext = decrypt_as_sender(parsed.ciphertext, parsed.nonce, alice_seed)
    assert plaintext == h(v["sender_self_decryption"]["plaintext"])
    assert h(v["sender_self_decryption"]["unsealed_recipient"]) == h(
        v["bob"]["sr25519_public"]
    )


def test_thread_message() -> None:
    v = load_vectors()
    alice_seed = Seed.from_bytes(h(v["alice"]["seed"]))
    bob_pub = pubkey_from_bytes(h(v["bob"]["sr25519_public"]))
    bob_scalar = sr25519_signing_scalar(Seed.from_bytes(h(v["bob"]["seed"])))
    nonce = nonce_from_bytes(h(v["thread_message"]["nonce"]))

    th = _br(v["thread_message"]["thread_ref"])
    rt = _br(v["thread_message"]["reply_to"])
    ct = _br(v["thread_message"]["continues"])
    thread_plaintext = encode_thread_content(th, rt, ct, h(v["thread_message"]["body"]))
    assert thread_plaintext == h(v["thread_message"]["thread_plaintext"])

    encrypted = encrypt(plaintext_from_bytes(thread_plaintext), bob_pub, nonce, alice_seed)
    assert encrypted == h(v["thread_message"]["encrypted_content"])

    parsed = decode_remark(h(v["thread_message"]["remark"]))
    from samp.wire import ThreadRemark

    assert isinstance(parsed, ThreadRemark)
    decrypted = decrypt(parsed.ciphertext, parsed.nonce, bob_scalar)
    thread, reply_to, _continues, body = decode_thread_content(decrypted)
    assert thread == th
    assert reply_to == rt
    assert body == h(v["thread_message"]["body"])


def test_channel_message_encoding() -> None:
    v = load_vectors()
    ch = v["channel_message"]
    remark = encode_channel_msg(
        _br(ch["channel_ref"]),
        _br(ch["reply_to"]),
        _br(ch["continues"]),
        h(ch["body"]),
    )
    assert remark == h(ch["remark"])


def test_channel_message_decoding() -> None:
    v = load_vectors()
    remark = h(v["channel_message"]["remark"])
    parsed = decode_remark(remark)
    assert isinstance(parsed, ChannelRemark)


def test_channel_create_encoding() -> None:
    v = load_vectors()
    ch = v["channel_create"]
    remark = encode_channel_create(
        ChannelName.parse(ch["name"]),
        ChannelDescription.parse(ch["description"]),
    )
    assert remark == h(ch["remark"])


def test_channel_create_decoding() -> None:
    v = load_vectors()
    remark = h(v["channel_create"]["remark"])
    parsed = decode_remark(remark)
    assert isinstance(parsed, ChannelCreateRemark)
    assert parsed.name.as_str() == v["channel_create"]["name"]
    assert parsed.description.as_str() == v["channel_create"]["description"]


def test_conformance_group_remark() -> None:
    v = load_vectors()
    remark = h(v["group_message"]["remark"])
    parsed = decode_remark(remark)
    assert isinstance(parsed, GroupRemark)


def test_conformance_group_member_list() -> None:
    v = load_vectors()
    members = [pubkey_from_bytes(h(m)) for m in v["group_message"]["members"]]
    encoded = encode_group_members(members)
    assert encoded == h(v["group_message"]["member_list_encoded"])


def test_conformance_group_decrypt_by_member() -> None:
    v = load_vectors()
    bob_seed = Seed.from_bytes(h(v["bob"]["seed"]))
    bob_scalar = sr25519_signing_scalar(bob_seed)
    parsed = decode_remark(h(v["group_message"]["remark"]))
    assert isinstance(parsed, GroupRemark)
    plaintext = decrypt_from_group(parsed.content, bob_scalar, parsed.nonce)
    assert plaintext == h(v["group_message"]["root_plaintext"])


def test_edge_empty_body_public() -> None:
    v = load_vectors()
    parsed = decode_remark(h(v["edge_cases"]["empty_body_public"]))
    assert isinstance(parsed, PublicRemark)
    assert parsed.body == ""


def test_edge_min_encrypted() -> None:
    v = load_vectors()
    parsed = decode_remark(h(v["edge_cases"]["min_encrypted"]))
    assert isinstance(parsed, EncryptedRemark)


def test_edge_empty_desc_channel_create() -> None:
    v = load_vectors()
    parsed = decode_remark(h(v["edge_cases"]["empty_desc_channel_create"]))
    assert isinstance(parsed, ChannelCreateRemark)
    assert parsed.name.as_str() == "test"
    assert parsed.description.as_str() == ""


def test_negative_non_samp_version() -> None:
    v = load_vectors()
    with pytest.raises(SampError):
        decode_remark(h(v["negative_cases"]["non_samp_version"]))


def test_negative_reserved_type() -> None:
    v = load_vectors()
    with pytest.raises(SampError):
        decode_remark(h(v["negative_cases"]["reserved_type"]))


def test_negative_truncated_encrypted() -> None:
    v = load_vectors()
    with pytest.raises(SampError):
        decode_remark(h(v["negative_cases"]["truncated_encrypted"]))
