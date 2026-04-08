from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from samp.error import SampError

SAMP_VERSION = 0x10

CHANNEL_HEADER_SIZE = 12
CHANNEL_NAME_MAX = 32
CHANNEL_DESC_MAX = 128
THREAD_HEADER_SIZE = 18
CAPSULE_SIZE = 33


class ContentType(IntEnum):
    PUBLIC = 0x10
    ENCRYPTED = 0x11
    THREAD = 0x12
    CHANNEL_CREATE = 0x13
    CHANNEL = 0x14
    GROUP = 0x15


def content_type_from_byte(b: int) -> ContentType:
    if b & 0xF0 != SAMP_VERSION:
        raise SampError(f"unsupported version: 0x{b & 0xF0:02x}")
    lower = b & 0x0F
    if lower in (0x06, 0x07):
        raise SampError(f"reserved content type: 0x{b:02x}")
    return ContentType(b)


def _encode_ref(ref: tuple[int, int]) -> bytes:
    return ref[0].to_bytes(4, "little") + ref[1].to_bytes(2, "little")


def _decode_ref(data: bytes, offset: int) -> tuple[int, int]:
    return (
        int.from_bytes(data[offset : offset + 4], "little"),
        int.from_bytes(data[offset + 4 : offset + 6], "little"),
    )


@dataclass(frozen=True)
class Remark:
    content_type: ContentType
    recipient: bytes
    view_tag: int
    nonce: bytes
    content: bytes


def encode_public(recipient: bytes, body: bytes) -> bytes:
    return bytes([ContentType.PUBLIC]) + recipient + body


def encode_encrypted(content_type: ContentType, view_tag: int, nonce: bytes, encrypted_content: bytes) -> bytes:
    return bytes([content_type, view_tag]) + nonce + encrypted_content


def encode_channel_msg(
    channel_ref: tuple[int, int],
    reply_to: tuple[int, int],
    continues: tuple[int, int],
    body: bytes,
) -> bytes:
    return (
        bytes([ContentType.CHANNEL])
        + _encode_ref(channel_ref)
        + _encode_ref(reply_to)
        + _encode_ref(continues)
        + body
    )


def encode_channel_create(name: str, description: str) -> bytes:
    name_bytes = name.encode("utf-8")
    desc_bytes = description.encode("utf-8")
    if not name_bytes or len(name_bytes) > CHANNEL_NAME_MAX:
        raise SampError(f"channel name must be 1-{CHANNEL_NAME_MAX} bytes")
    if len(desc_bytes) > CHANNEL_DESC_MAX:
        raise SampError(f"channel description must be 0-{CHANNEL_DESC_MAX} bytes")
    return (
        bytes([ContentType.CHANNEL_CREATE, len(name_bytes)])
        + name_bytes
        + bytes([len(desc_bytes)])
        + desc_bytes
    )


def encode_group(nonce: bytes, eph_pubkey: bytes, capsules: bytes, ciphertext: bytes) -> bytes:
    return bytes([ContentType.GROUP]) + nonce + eph_pubkey + capsules + ciphertext


def decode_remark(data: bytes) -> Remark:
    if len(data) == 0:
        raise SampError("insufficient data")

    ct = content_type_from_byte(data[0])

    if ct == ContentType.PUBLIC:
        if len(data) < 33:
            raise SampError("insufficient data for public message")
        recipient = data[1:33]
        body = data[33:]
        body.decode("utf-8")
        return Remark(
            content_type=ct,
            recipient=recipient,
            view_tag=0,
            nonce=b"\x00" * 12,
            content=body,
        )

    if ct in (ContentType.ENCRYPTED, ContentType.THREAD):
        if len(data) < 14:
            raise SampError("insufficient data for encrypted message")
        return Remark(
            content_type=ct,
            recipient=b"\x00" * 32,
            view_tag=data[1],
            nonce=data[2:14],
            content=data[14:],
        )

    if ct == ContentType.CHANNEL_CREATE:
        return Remark(
            content_type=ct,
            recipient=b"\x00" * 32,
            view_tag=0,
            nonce=b"\x00" * 12,
            content=data[1:],
        )

    if ct == ContentType.CHANNEL:
        if len(data) < 19:
            raise SampError("insufficient data for channel message")
        block_num = int.from_bytes(data[1:5], "little")
        ext_idx = int.from_bytes(data[5:7], "little")
        recipient = (
            block_num.to_bytes(4, "little")
            + ext_idx.to_bytes(2, "little")
            + b"\x00" * 26
        )
        return Remark(
            content_type=ct,
            recipient=recipient,
            view_tag=0,
            nonce=b"\x00" * 12,
            content=data[7:],
        )

    if ct == ContentType.GROUP:
        if len(data) < 45:
            raise SampError("insufficient data for group message")
        return Remark(
            content_type=ct,
            recipient=b"\x00" * 32,
            view_tag=0,
            nonce=data[1:13],
            content=data[13:],
        )

    raise SampError(f"unhandled content type: 0x{int(ct):02x}")


def encode_thread_content(
    thread: tuple[int, int],
    reply_to: tuple[int, int],
    continues: tuple[int, int],
    body: bytes,
) -> bytes:
    return _encode_ref(thread) + _encode_ref(reply_to) + _encode_ref(continues) + body


def decode_thread_content(
    content: bytes,
) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int], bytes]:
    if len(content) < THREAD_HEADER_SIZE:
        raise SampError("insufficient data for thread header")
    return _decode_ref(content, 0), _decode_ref(content, 6), _decode_ref(content, 12), content[18:]


def encode_channel_content(
    reply_to: tuple[int, int], continues: tuple[int, int], body: bytes
) -> bytes:
    return _encode_ref(reply_to) + _encode_ref(continues) + body


def decode_channel_content(
    content: bytes,
) -> tuple[tuple[int, int], tuple[int, int], bytes]:
    if len(content) < CHANNEL_HEADER_SIZE:
        raise SampError("insufficient data for channel header")
    return _decode_ref(content, 0), _decode_ref(content, 6), content[12:]


def decode_channel_create(data: bytes) -> tuple[str, str]:
    if len(data) < 2:
        raise SampError("insufficient data for channel create")
    name_len = data[0]
    if name_len == 0 or name_len > CHANNEL_NAME_MAX:
        raise SampError(f"channel name must be 1-{CHANNEL_NAME_MAX} bytes")
    if len(data) < 1 + name_len + 1:
        raise SampError("insufficient data for channel name")
    name = data[1 : 1 + name_len].decode("utf-8")
    desc_offset = 1 + name_len
    desc_len = data[desc_offset]
    if desc_len > CHANNEL_DESC_MAX:
        raise SampError(f"channel description must be 0-{CHANNEL_DESC_MAX} bytes")
    if len(data) < desc_offset + 1 + desc_len:
        raise SampError("insufficient data for channel description")
    description = data[desc_offset + 1 : desc_offset + 1 + desc_len].decode("utf-8")
    return name, description


def decode_group_content(
    content: bytes,
) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int], bytes]:
    if len(content) < THREAD_HEADER_SIZE:
        raise SampError("insufficient data for group content header")
    return _decode_ref(content, 0), _decode_ref(content, 6), _decode_ref(content, 12), content[18:]


def encode_group_members(member_pubkeys: list[bytes]) -> bytes:
    out = bytes([len(member_pubkeys)])
    for pk in member_pubkeys:
        out += pk
    return out


def decode_group_members(data: bytes) -> tuple[list[bytes], bytes]:
    if len(data) < 1:
        raise SampError("insufficient data for group members")
    count = data[0]
    expected = 1 + count * 32
    if len(data) < expected:
        raise SampError("insufficient data for group members")
    members = []
    for i in range(count):
        start = 1 + i * 32
        members.append(data[start:start + 32])
    return members, data[expected:]


def channel_ref_from_recipient(recipient: bytes) -> tuple[int, int]:
    block = int.from_bytes(recipient[0:4], "little")
    index = int.from_bytes(recipient[4:6], "little")
    return block, index
