import json
from pathlib import Path

import pytest
import samp_crypto

from samp import (
    SampError,
    decode_remark,
    encrypt,
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

def load_vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text())

def h(s: str) -> bytes:
    return bytes.fromhex(s.removeprefix("0x"))

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
    assert parsed.content_type == ContentType.PUBLIC
    assert parsed.content == h(v["public_message"]["body"])

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

    remark = encode_encrypted(ContentType.ENCRYPTED, view_tag, nonce, encrypted_content)
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
    assert parsed.content_type == ContentType.ENCRYPTED
    assert parsed.view_tag == v["encrypted_message"]["view_tag"]
    assert parsed.nonce == h(v["encrypted_message"]["nonce"])

def test_encrypted_recipient_decryption():
    v = load_vectors()
    bob_seed = h(v["bob"]["seed"])
    bob_scalar = samp_crypto.sr25519_signing_scalar(bob_seed)
    parsed = decode_remark(h(v["encrypted_message"]["remark"]))
    plaintext = decrypt(parsed, bob_scalar)
    assert plaintext == h(v["encrypted_message"]["plaintext"])

def test_sender_self_decryption():
    v = load_vectors()
    alice_seed = h(v["alice"]["seed"])
    parsed = decode_remark(h(v["encrypted_message"]["remark"]))
    plaintext = decrypt_as_sender(parsed, alice_seed)
    assert plaintext == h(v["sender_self_decryption"]["plaintext"])
    assert h(v["sender_self_decryption"]["unsealed_recipient"]) == h(v["bob"]["sr25519_public"])

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

    parsed = decode_remark(h(v["thread_message"]["remark"]))
    decrypted = decrypt(parsed, bob_scalar)
    thread, reply_to, _continues, body = decode_thread_content(decrypted)
    assert thread == (th[0], th[1])
    assert reply_to == (rt[0], rt[1])
    assert body == h(v["thread_message"]["body"])

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
    assert parsed.content_type == ContentType.CHANNEL

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

def test_conformance_group_remark():
    v = load_vectors()
    remark = h(v["group_message"]["remark"])
    parsed = decode_remark(remark)
    assert parsed.content_type == ContentType.GROUP

def test_conformance_group_member_list():
    v = load_vectors()
    members = [h(m) for m in v["group_message"]["members"]]
    encoded = encode_group_members(members)
    assert encoded == h(v["group_message"]["member_list_encoded"])

def test_conformance_group_decrypt_by_member():
    v = load_vectors()
    bob_seed = h(v["bob"]["seed"])
    bob_scalar = samp_crypto.sr25519_signing_scalar(bob_seed)
    parsed = decode_remark(h(v["group_message"]["remark"]))
    plaintext = decrypt_from_group(parsed.content, bob_scalar, parsed.nonce)
    assert plaintext == h(v["group_message"]["root_plaintext"])

def test_edge_empty_body_public():
    v = load_vectors()
    parsed = decode_remark(h(v["edge_cases"]["empty_body_public"]))
    assert parsed.content_type == ContentType.PUBLIC
    assert parsed.content == b""

def test_edge_min_encrypted():
    v = load_vectors()
    parsed = decode_remark(h(v["edge_cases"]["min_encrypted"]))
    assert parsed.content_type == ContentType.ENCRYPTED

def test_edge_empty_desc_channel_create():
    v = load_vectors()
    parsed = decode_remark(h(v["edge_cases"]["empty_desc_channel_create"]))
    name, desc = decode_channel_create(parsed.content)
    assert name == "test"
    assert desc == ""

def test_negative_non_samp_version():
    v = load_vectors()
    with pytest.raises(SampError):
        decode_remark(h(v["negative_cases"]["non_samp_version"]))

def test_negative_reserved_type():
    v = load_vectors()
    with pytest.raises(SampError):
        decode_remark(h(v["negative_cases"]["reserved_type"]))

def test_negative_truncated_encrypted():
    v = load_vectors()
    with pytest.raises(SampError):
        decode_remark(h(v["negative_cases"]["truncated_encrypted"]))
