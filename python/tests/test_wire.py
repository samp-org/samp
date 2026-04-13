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


# --- content_type_from_byte: reserved types ---


def test_content_type_reserved_0x06() -> None:
    from samp.wire import content_type_from_byte

    with pytest.raises(SampError):
        content_type_from_byte(0x16)


def test_content_type_reserved_0x07() -> None:
    from samp.wire import content_type_from_byte

    with pytest.raises(SampError):
        content_type_from_byte(0x17)


def test_content_type_bad_version() -> None:
    from samp.wire import content_type_from_byte

    with pytest.raises(SampError):
        content_type_from_byte(0x20)


def test_content_type_application() -> None:
    from samp.wire import ContentType, content_type_from_byte

    assert content_type_from_byte(0x18) == ContentType.APPLICATION
    assert content_type_from_byte(0x1F) == ContentType.APPLICATION


def test_content_type_all_valid() -> None:
    from samp.wire import ContentType, content_type_from_byte

    assert content_type_from_byte(0x10) == ContentType.PUBLIC
    assert content_type_from_byte(0x11) == ContentType.ENCRYPTED
    assert content_type_from_byte(0x12) == ContentType.THREAD
    assert content_type_from_byte(0x13) == ContentType.CHANNEL_CREATE
    assert content_type_from_byte(0x14) == ContentType.CHANNEL
    assert content_type_from_byte(0x15) == ContentType.GROUP


# --- encode_encrypted: rejects non-ENCRYPTED/THREAD ---


def test_encode_encrypted_rejects_public() -> None:
    from samp import ContentType, nonce_from_bytes, ciphertext_from_bytes
    from samp.wire import encode_encrypted

    with pytest.raises(SampError):
        encode_encrypted(
            ContentType.PUBLIC,
            view_tag_from_int(0),
            nonce_from_bytes(bytes(12)),
            ciphertext_from_bytes(b"\x00" * 80),
        )


# --- decode_remark: public message UTF-8 errors ---


def test_decode_public_remark_utf8_error() -> None:
    recipient = bytes(32)
    bad_body = b"\xff\xfe"
    data = bytes([0x10]) + recipient + bad_body
    with pytest.raises(SampError, match="utf-8"):
        decode_remark(remark_bytes_from_bytes(data))


def test_decode_public_remark_truncated() -> None:
    data = bytes([0x10]) + bytes(10)
    with pytest.raises(SampError):
        decode_remark(remark_bytes_from_bytes(data))


# --- decode_remark: channel message edges ---


def test_decode_channel_message_truncated() -> None:
    data = bytes([0x14]) + bytes(10)
    with pytest.raises(SampError):
        decode_remark(remark_bytes_from_bytes(data))


def test_decode_channel_message_utf8_error() -> None:
    data = bytes([0x14]) + bytes(18) + b"\xff\xfe"
    with pytest.raises(SampError, match="utf-8"):
        decode_remark(remark_bytes_from_bytes(data))


# --- decode_remark: group message truncated ---


def test_decode_group_message_truncated() -> None:
    data = bytes([0x15]) + bytes(5)
    with pytest.raises(SampError):
        decode_remark(remark_bytes_from_bytes(data))


# --- decode_remark: application content type ---


def test_decode_application_remark() -> None:
    from samp import ApplicationRemark

    data = bytes([0x18]) + b"\x01\x02\x03"
    result = decode_remark(remark_bytes_from_bytes(data))
    assert isinstance(result, ApplicationRemark)
    assert result.tag == 0x18
    assert result.payload == b"\x01\x02\x03"


# --- decode_remark: reserved in decode path ---


def test_decode_remark_reserved_0x16() -> None:
    data = bytes([0x16]) + bytes(10)
    with pytest.raises(SampError):
        decode_remark(remark_bytes_from_bytes(data))


# --- decode_channel_create: edge cases ---


def test_decode_channel_create_too_short() -> None:
    from samp.wire import decode_channel_create

    with pytest.raises(SampError):
        decode_channel_create(b"\x05")


def test_decode_channel_create_empty_name() -> None:
    from samp.wire import decode_channel_create

    with pytest.raises(SampError):
        decode_channel_create(bytes([0x00, 0x00]))


def test_decode_channel_create_name_too_long() -> None:
    from samp.wire import decode_channel_create

    with pytest.raises(SampError):
        decode_channel_create(bytes([0xFF]) + bytes(255))


def test_decode_channel_create_truncated_name() -> None:
    from samp.wire import decode_channel_create

    with pytest.raises(SampError):
        decode_channel_create(bytes([0x05]) + b"ab")


def test_decode_channel_create_name_utf8_error() -> None:
    from samp.wire import decode_channel_create

    with pytest.raises(SampError, match="utf-8"):
        decode_channel_create(bytes([0x02, 0xFF, 0xFE, 0x00]))


def test_decode_channel_create_desc_too_long() -> None:
    from samp.wire import decode_channel_create

    name = b"ok"
    data = bytes([len(name)]) + name + bytes([0xFF]) + bytes(255)
    with pytest.raises(SampError):
        decode_channel_create(data)


def test_decode_channel_create_truncated_desc() -> None:
    from samp.wire import decode_channel_create

    name = b"ok"
    data = bytes([len(name)]) + name + bytes([0x05]) + b"ab"
    with pytest.raises(SampError):
        decode_channel_create(data)


def test_decode_channel_create_desc_utf8_error() -> None:
    from samp.wire import decode_channel_create

    name = b"ok"
    data = bytes([len(name)]) + name + bytes([0x02]) + b"\xff\xfe"
    with pytest.raises(SampError, match="utf-8"):
        decode_channel_create(data)


# --- decode_group_content: truncated ---


def test_decode_group_content_truncated() -> None:
    from samp.wire import decode_group_content

    with pytest.raises(SampError):
        decode_group_content(b"\x00" * 5)


# --- decode_channel_content: truncated ---


def test_decode_channel_content_truncated() -> None:
    from samp.wire import decode_channel_content

    with pytest.raises(SampError):
        decode_channel_content(b"\x00" * 5)


# --- decode_group_members: edges ---


def test_decode_group_members_empty() -> None:
    from samp.wire import decode_group_members

    with pytest.raises(SampError):
        decode_group_members(b"")


def test_decode_group_members_truncated() -> None:
    from samp.wire import decode_group_members

    with pytest.raises(SampError):
        decode_group_members(bytes([0x02]) + bytes(32))
