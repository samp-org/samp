"""SAMP v0.2 conformance tests against shared test vectors."""

import json
from pathlib import Path

import samp_crypto

from samp import (
    SampError,
    decode_remark,
    encrypt,
)
from samp.encryption import compute_view_tag, decrypt, decrypt_as_sender, decrypt_from_group
from samp.wire import (
    CONTENT_TYPE_CHANNEL,
    CONTENT_TYPE_ENCRYPTED,
    CONTENT_TYPE_GROUP,
    CONTENT_TYPE_PUBLIC,
    CONTENT_TYPE_THREAD,
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


def load_vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text())


def h(s: str) -> bytes:
    return bytes.fromhex(s.removeprefix("0x"))


# --- Keypair derivation ---


def test_keypair_alice():
    v = load_vectors()
    seed = h(v["alice"]["seed"])
    pub = samp_crypto.public_from_seed(seed)
    assert pub == h(v["alice"]["sr25519_public"])
    scalar = samp_crypto.sr25519_signing_scalar(seed)
    assert scalar == h(v["alice"]["signing_scalar"])


def test_keypair_bob():
    v = load_vectors()
    seed = h(v["bob"]["seed"])
    pub = samp_crypto.public_from_seed(seed)
    assert pub == h(v["bob"]["sr25519_public"])
    scalar = samp_crypto.sr25519_signing_scalar(seed)
    assert scalar == h(v["bob"]["signing_scalar"])


# --- Public message ---


def test_public_message_encoding():
    v = load_vectors()
    bob_pub = h(v["bob"]["sr25519_public"])
    body = h(v["public_message"]["body"])
    remark = encode_public(bob_pub, body)
    assert remark == h(v["public_message"]["remark"])


def test_public_message_decoding():
    v = load_vectors()
    remark = h(v["public_message"]["remark"])
    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_PUBLIC
    assert parsed.content == h(v["public_message"]["body"])


# --- Encrypted message ---


def test_encrypted_message_encoding():
    v = load_vectors()
    alice_seed = h(v["alice"]["seed"])
    bob_pub = h(v["bob"]["sr25519_public"])
    nonce = h(v["encrypted_message"]["nonce"])
    plaintext = h(v["encrypted_message"]["plaintext"])

    encrypted_content = encrypt(plaintext, bob_pub, nonce, alice_seed)
    assert encrypted_content == h(v["encrypted_message"]["encrypted_content"])

    view_tag = compute_view_tag(alice_seed, bob_pub, nonce)
    assert view_tag == v["encrypted_message"]["view_tag"]

    remark = encode_encrypted(CONTENT_TYPE_ENCRYPTED, view_tag, nonce, encrypted_content)
    assert remark == h(v["encrypted_message"]["remark"])


def test_encrypted_message_intermediates():
    v = load_vectors()
    content = h(v["encrypted_message"]["encrypted_content"])
    assert content[:32] == h(v["encrypted_message"]["ephemeral_pubkey"])
    assert content[32:64] == h(v["encrypted_message"]["sealed_to"])
    assert content[64:] == h(v["encrypted_message"]["ciphertext_with_tag"])


def test_encrypted_message_decoding():
    v = load_vectors()
    remark = h(v["encrypted_message"]["remark"])
    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_ENCRYPTED
    assert parsed.view_tag == v["encrypted_message"]["view_tag"]
    assert parsed.nonce == h(v["encrypted_message"]["nonce"])


def test_encrypted_recipient_decryption():
    v = load_vectors()
    bob_seed = h(v["bob"]["seed"])
    bob_scalar = samp_crypto.sr25519_signing_scalar(bob_seed)
    nonce = h(v["encrypted_message"]["nonce"])
    encrypted_content = h(v["encrypted_message"]["encrypted_content"])
    plaintext = decrypt(encrypted_content, bob_scalar, nonce)
    assert plaintext == h(v["encrypted_message"]["plaintext"])


# --- Sender self-decryption ---


def test_sender_self_decryption():
    v = load_vectors()
    alice_seed = h(v["alice"]["seed"])
    nonce = h(v["encrypted_message"]["nonce"])
    encrypted_content = h(v["encrypted_message"]["encrypted_content"])
    plaintext = decrypt_as_sender(encrypted_content, alice_seed, nonce)
    assert plaintext == h(v["sender_self_decryption"]["plaintext"])
    assert h(v["sender_self_decryption"]["unsealed_recipient"]) == h(v["bob"]["sr25519_public"])


# --- Thread message ---


def test_thread_message():
    v = load_vectors()
    alice_seed = h(v["alice"]["seed"])
    bob_pub = h(v["bob"]["sr25519_public"])
    bob_scalar = samp_crypto.sr25519_signing_scalar(h(v["bob"]["seed"]))
    nonce = h(v["thread_message"]["nonce"])

    th = v["thread_message"]["thread_ref"]
    rt = v["thread_message"]["reply_to"]
    ct = v["thread_message"]["continues"]
    thread_plaintext = encode_thread_content(
        (th[0], th[1]), (rt[0], rt[1]), (ct[0], ct[1]),
        h(v["thread_message"]["body"]),
    )
    assert thread_plaintext == h(v["thread_message"]["thread_plaintext"])

    encrypted = encrypt(thread_plaintext, bob_pub, nonce, alice_seed)
    assert encrypted == h(v["thread_message"]["encrypted_content"])

    decrypted = decrypt(encrypted, bob_scalar, nonce)
    thread, reply_to, continues, body = decode_thread_content(decrypted)
    assert thread == (th[0], th[1])
    assert reply_to == (rt[0], rt[1])
    assert body == h(v["thread_message"]["body"])


# --- Channel message ---


def test_channel_message_encoding():
    v = load_vectors()
    ch = v["channel_message"]
    remark = encode_channel_msg(
        tuple(ch["channel_ref"]),
        tuple(ch["reply_to"]),
        tuple(ch["continues"]),
        h(ch["body"]),
    )
    assert remark == h(ch["remark"])


def test_channel_message_decoding():
    v = load_vectors()
    remark = h(v["channel_message"]["remark"])
    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_CHANNEL


# --- Channel creation ---


def test_channel_create_encoding():
    v = load_vectors()
    ch = v["channel_create"]
    remark = encode_channel_create(ch["name"], ch["description"])
    assert remark == h(ch["remark"])


def test_channel_create_decoding():
    v = load_vectors()
    remark = h(v["channel_create"]["remark"])
    parsed = decode_remark(remark)
    name, desc = decode_channel_create(parsed.content)
    assert name == v["channel_create"]["name"]
    assert desc == v["channel_create"]["description"]


# --- Group message ---


def test_conformance_group_remark():
    v = load_vectors()
    remark = h(v["group_message"]["remark"])
    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_GROUP


def test_conformance_group_member_list():
    v = load_vectors()
    members = [h(m) for m in v["group_message"]["members"]]
    encoded = encode_group_members(members)
    assert encoded == h(v["group_message"]["member_list_encoded"])


def test_conformance_group_decrypt_by_member():
    v = load_vectors()
    bob_seed = h(v["bob"]["seed"])
    bob_scalar = samp_crypto.sr25519_signing_scalar(bob_seed)
    remark = h(v["group_message"]["remark"])
    parsed = decode_remark(remark)
    plaintext = decrypt_from_group(parsed.content, bob_scalar, parsed.nonce)
    assert plaintext == h(v["group_message"]["root_plaintext"])


# --- Edge cases ---


def test_edge_empty_body_public():
    v = load_vectors()
    remark = h(v["edge_cases"]["empty_body_public"])
    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_PUBLIC
    assert parsed.content == b""


def test_edge_min_encrypted():
    v = load_vectors()
    remark = h(v["edge_cases"]["min_encrypted"])
    parsed = decode_remark(remark)
    assert parsed.content_type == CONTENT_TYPE_ENCRYPTED


def test_edge_empty_desc_channel_create():
    v = load_vectors()
    remark = h(v["edge_cases"]["empty_desc_channel_create"])
    parsed = decode_remark(remark)
    name, desc = decode_channel_create(parsed.content)
    assert name == "test"
    assert desc == ""


# --- Negative cases ---


def test_negative_non_samp_version():
    v = load_vectors()
    try:
        decode_remark(h(v["negative_cases"]["non_samp_version"]))
        assert False, "should have raised"
    except SampError:
        pass


def test_negative_reserved_type():
    v = load_vectors()
    try:
        decode_remark(h(v["negative_cases"]["reserved_type"]))
        assert False, "should have raised"
    except SampError:
        pass


def test_negative_truncated_encrypted():
    v = load_vectors()
    try:
        decode_remark(h(v["negative_cases"]["truncated_encrypted"]))
        assert False, "should have raised"
    except SampError:
        pass
