from __future__ import annotations

import pytest

from samp import (
    ChannelCreateRemark,
    ChannelDescription,
    ChannelName,
    SampError,
    decode_remark,
    view_tag_from_int,
    remark_bytes_from_bytes,
)
from samp.wire import (
    decode_thread_content,
    encode_channel_create,
    is_samp_remark,
)


def test_decode_remark_empty() -> None:
    with pytest.raises(SampError):
        decode_remark(remark_bytes_from_bytes(b""))


def test_is_samp_remark_false() -> None:
    assert is_samp_remark(b"\x20\x00") is False


def test_channel_create_round_trip() -> None:
    name = ChannelName.parse("general")
    desc = ChannelDescription.parse("A test channel")
    encoded = encode_channel_create(name, desc)
    decoded = decode_remark(encoded)
    assert isinstance(decoded, ChannelCreateRemark)
    assert decoded.name.as_str() == "general"
    assert decoded.description.as_str() == "A test channel"


def test_decode_thread_content_truncated() -> None:
    with pytest.raises(SampError):
        decode_thread_content(b"\x00" * 5)


def test_encode_encrypted_round_trip() -> None:
    from samp import (
        ContentType,
        EncryptedRemark,
        Seed,
        encrypt,
        nonce_from_bytes,
        plaintext_from_bytes,
    )
    from samp.encryption import public_from_seed
    from samp.wire import encode_encrypted

    sender_seed = Seed.from_bytes(bytes([0xAA] * 32))
    recipient_pub = public_from_seed(Seed.from_bytes(bytes([0xBB] * 32)))
    nonce = nonce_from_bytes(bytes([0x01] * 12))
    pt = plaintext_from_bytes(b"round trip test")

    ct = encrypt(pt, recipient_pub, nonce, sender_seed)
    encoded = encode_encrypted(ContentType.ENCRYPTED, view_tag_from_int(0), nonce, ct)
    decoded = decode_remark(encoded)
    assert isinstance(decoded, EncryptedRemark)
    assert bytes(decoded.nonce) == bytes(nonce)
    assert bytes(decoded.ciphertext) == bytes(ct)


def test_encode_group_members_round_trip() -> None:
    from samp import pubkey_from_bytes
    from samp.wire import decode_group_members, encode_group_members

    pk1 = pubkey_from_bytes(bytes([0x01] * 32))
    pk2 = pubkey_from_bytes(bytes([0x02] * 32))
    encoded = encode_group_members([pk1, pk2])
    members, rest = decode_group_members(encoded)
    assert len(members) == 2
    assert bytes(members[0]) == bytes(pk1)
    assert bytes(members[1]) == bytes(pk2)
    assert rest == b""


def test_decode_group_members_round_trip() -> None:
    from samp import pubkey_from_bytes
    from samp.wire import decode_group_members, encode_group_members

    pk1 = pubkey_from_bytes(bytes([0xAA] * 32))
    pk2 = pubkey_from_bytes(bytes([0xBB] * 32))
    pk3 = pubkey_from_bytes(bytes([0xCC] * 32))
    encoded = encode_group_members([pk1, pk2, pk3])
    members, rest = decode_group_members(encoded)
    assert len(members) == 3
    assert bytes(members[0]) == bytes(pk1)
    assert bytes(members[1]) == bytes(pk2)
    assert bytes(members[2]) == bytes(pk3)
    assert rest == b""
