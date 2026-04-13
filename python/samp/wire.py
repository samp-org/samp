from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Union

from samp.error import SampError
from samp.types import (
    CAPSULE_SIZE,
    CHANNEL_DESC_MAX,
    CHANNEL_NAME_MAX,
    BlockRef,
    Capsules,
    ChannelDescription,
    ChannelName,
    Ciphertext,
    EphPubkey,
    Nonce,
    Pubkey,
    RemarkBytes,
    ViewTag,
    block_number_from_int,
    ciphertext_from_bytes,
    ext_index_from_int,
    nonce_from_bytes,
    pubkey_from_bytes,
    remark_bytes_from_bytes,
    view_tag_from_int,
)

SAMP_VERSION = 0x10
CHANNEL_HEADER_SIZE = 12
THREAD_HEADER_SIZE = 18

__all__ = [
    "SAMP_VERSION",
    "CAPSULE_SIZE",
    "CHANNEL_NAME_MAX",
    "CHANNEL_DESC_MAX",
    "CHANNEL_HEADER_SIZE",
    "THREAD_HEADER_SIZE",
    "ContentType",
    "content_type_from_byte",
    "is_samp_remark",
    "PublicRemark",
    "EncryptedRemark",
    "ThreadRemark",
    "ChannelCreateRemark",
    "ChannelRemark",
    "GroupRemark",
    "ApplicationRemark",
    "Remark",
    "encode_public",
    "encode_encrypted",
    "encode_channel_create",
    "encode_channel_msg",
    "encode_group",
    "decode_remark",
    "encode_thread_content",
    "decode_thread_content",
    "encode_channel_content",
    "decode_channel_content",
    "decode_channel_create",
    "decode_group_content",
    "encode_group_members",
    "decode_group_members",
]


class ContentType(IntEnum):
    PUBLIC = 0x10
    ENCRYPTED = 0x11
    THREAD = 0x12
    CHANNEL_CREATE = 0x13
    CHANNEL = 0x14
    GROUP = 0x15
    APPLICATION = 0x18


def content_type_from_byte(b: int) -> ContentType:
    if b & 0xF0 != SAMP_VERSION:
        raise SampError(f"unsupported version: 0x{b & 0xF0:02x}")
    lower = b & 0x0F
    if lower == 0x00:
        return ContentType.PUBLIC
    if lower == 0x01:
        return ContentType.ENCRYPTED
    if lower == 0x02:
        return ContentType.THREAD
    if lower == 0x03:
        return ContentType.CHANNEL_CREATE
    if lower == 0x04:
        return ContentType.CHANNEL
    if lower == 0x05:
        return ContentType.GROUP
    if lower in (0x06, 0x07):
        raise SampError(f"reserved content type: 0x{b:02x}")
    return ContentType.APPLICATION


def is_samp_remark(data: bytes) -> bool:
    return len(data) > 0 and (data[0] & 0xF0) == SAMP_VERSION


@dataclass(frozen=True)
class PublicRemark:
    recipient: Pubkey
    body: str


@dataclass(frozen=True)
class EncryptedRemark:
    view_tag: ViewTag
    nonce: Nonce
    ciphertext: Ciphertext


@dataclass(frozen=True)
class ThreadRemark:
    view_tag: ViewTag
    nonce: Nonce
    ciphertext: Ciphertext


@dataclass(frozen=True)
class ChannelCreateRemark:
    name: ChannelName
    description: ChannelDescription


@dataclass(frozen=True)
class ChannelRemark:
    channel_ref: BlockRef
    reply_to: BlockRef
    continues: BlockRef
    body: str


@dataclass(frozen=True)
class GroupRemark:
    nonce: Nonce
    content: bytes


@dataclass(frozen=True)
class ApplicationRemark:
    tag: int
    payload: bytes


Remark = Union[
    PublicRemark,
    EncryptedRemark,
    ThreadRemark,
    ChannelCreateRemark,
    ChannelRemark,
    GroupRemark,
    ApplicationRemark,
]


def _encode_ref(ref: BlockRef) -> bytes:
    return int(ref.number).to_bytes(4, "little") + int(ref.index).to_bytes(2, "little")


def _decode_ref(data: bytes, offset: int) -> BlockRef:
    return BlockRef.of(
        block_number_from_int(int.from_bytes(data[offset : offset + 4], "little")),
        ext_index_from_int(int.from_bytes(data[offset + 4 : offset + 6], "little")),
    )


def encode_public(recipient: Pubkey, body: str) -> RemarkBytes:
    body_bytes = body.encode("utf-8")
    return remark_bytes_from_bytes(bytes([ContentType.PUBLIC]) + recipient + body_bytes)


def encode_encrypted(
    content_type: ContentType,
    view_tag: ViewTag,
    nonce: Nonce,
    ciphertext: Ciphertext,
) -> RemarkBytes:
    if content_type not in (ContentType.ENCRYPTED, ContentType.THREAD):
        raise SampError(f"encode_encrypted requires ENCRYPTED or THREAD, got {content_type!r}")
    return remark_bytes_from_bytes(
        bytes([int(content_type), int(view_tag)]) + nonce + ciphertext
    )


def encode_channel_create(name: ChannelName, description: ChannelDescription) -> RemarkBytes:
    nb = name.as_str().encode("utf-8")
    db = description.as_str().encode("utf-8")
    return remark_bytes_from_bytes(
        bytes([ContentType.CHANNEL_CREATE, len(nb)]) + nb + bytes([len(db)]) + db
    )


def encode_channel_msg(
    channel_ref: BlockRef,
    reply_to: BlockRef,
    continues: BlockRef,
    body: str,
) -> RemarkBytes:
    return remark_bytes_from_bytes(
        bytes([ContentType.CHANNEL])
        + _encode_ref(channel_ref)
        + _encode_ref(reply_to)
        + _encode_ref(continues)
        + body.encode("utf-8")
    )


def encode_group(
    nonce: Nonce,
    eph_pubkey: EphPubkey,
    capsules: Capsules,
    ciphertext: Ciphertext,
) -> RemarkBytes:
    return remark_bytes_from_bytes(
        bytes([ContentType.GROUP]) + nonce + eph_pubkey + capsules + ciphertext
    )


def decode_remark(data: bytes) -> Remark:
    if len(data) == 0:
        raise SampError("insufficient data")
    ct_byte = data[0]
    if ct_byte & 0xF0 != SAMP_VERSION:
        raise SampError(f"unsupported version: 0x{ct_byte & 0xF0:02x}")
    lower = ct_byte & 0x0F

    if lower == 0x00:
        if len(data) < 33:
            raise SampError("insufficient data for public message")
        recipient = pubkey_from_bytes(data[1:33])
        try:
            body = data[33:].decode("utf-8")
        except UnicodeDecodeError as e:
            raise SampError("invalid utf-8") from e
        return PublicRemark(recipient=recipient, body=body)

    if lower in (0x01, 0x02):
        if len(data) < 14:
            raise SampError("insufficient data for encrypted message")
        view_tag = view_tag_from_int(data[1])
        nonce = nonce_from_bytes(data[2:14])
        ciphertext = ciphertext_from_bytes(data[14:])
        if lower == 0x01:
            return EncryptedRemark(view_tag=view_tag, nonce=nonce, ciphertext=ciphertext)
        return ThreadRemark(view_tag=view_tag, nonce=nonce, ciphertext=ciphertext)

    if lower == 0x03:
        name, description = decode_channel_create(data[1:])
        return ChannelCreateRemark(
            name=ChannelName.parse(name),
            description=ChannelDescription.parse(description),
        )

    if lower == 0x04:
        if len(data) < 19:
            raise SampError("insufficient data for channel message")
        try:
            body = data[19:].decode("utf-8")
        except UnicodeDecodeError as e:
            raise SampError("invalid utf-8") from e
        return ChannelRemark(
            channel_ref=_decode_ref(data, 1),
            reply_to=_decode_ref(data, 7),
            continues=_decode_ref(data, 13),
            body=body,
        )

    if lower == 0x05:
        if len(data) < 13:
            raise SampError("insufficient data for group message")
        return GroupRemark(
            nonce=nonce_from_bytes(data[1:13]),
            content=bytes(data[13:]),
        )

    if lower in (0x06, 0x07):
        raise SampError(f"reserved content type: 0x{ct_byte:02x}")

    return ApplicationRemark(tag=ct_byte, payload=bytes(data[1:]))


def encode_thread_content(
    thread: BlockRef,
    reply_to: BlockRef,
    continues: BlockRef,
    body: bytes,
) -> bytes:
    return _encode_ref(thread) + _encode_ref(reply_to) + _encode_ref(continues) + body


def decode_thread_content(content: bytes) -> tuple[BlockRef, BlockRef, BlockRef, bytes]:
    if len(content) < THREAD_HEADER_SIZE:
        raise SampError("insufficient data for thread header")
    return (
        _decode_ref(content, 0),
        _decode_ref(content, 6),
        _decode_ref(content, 12),
        bytes(content[18:]),
    )


def encode_channel_content(reply_to: BlockRef, continues: BlockRef, body: bytes) -> bytes:
    return _encode_ref(reply_to) + _encode_ref(continues) + body


def decode_channel_content(content: bytes) -> tuple[BlockRef, BlockRef, bytes]:
    if len(content) < CHANNEL_HEADER_SIZE:
        raise SampError("insufficient data for channel header")
    return _decode_ref(content, 0), _decode_ref(content, 6), bytes(content[12:])


def decode_channel_create(data: bytes) -> tuple[str, str]:
    if len(data) < 2:
        raise SampError("insufficient data for channel create")
    name_len = data[0]
    if name_len == 0 or name_len > CHANNEL_NAME_MAX:
        raise SampError(f"channel name must be 1-{CHANNEL_NAME_MAX} bytes")
    if len(data) < 1 + name_len + 1:
        raise SampError("insufficient data for channel name")
    try:
        name = data[1 : 1 + name_len].decode("utf-8")
    except UnicodeDecodeError as e:
        raise SampError("invalid utf-8") from e
    desc_offset = 1 + name_len
    desc_len = data[desc_offset]
    if desc_len > CHANNEL_DESC_MAX:
        raise SampError(f"channel description must be 0-{CHANNEL_DESC_MAX} bytes")
    if len(data) < desc_offset + 1 + desc_len:
        raise SampError("insufficient data for channel description")
    try:
        description = data[desc_offset + 1 : desc_offset + 1 + desc_len].decode("utf-8")
    except UnicodeDecodeError as e:
        raise SampError("invalid utf-8") from e
    return name, description


def decode_group_content(content: bytes) -> tuple[BlockRef, BlockRef, BlockRef, bytes]:
    if len(content) < THREAD_HEADER_SIZE:
        raise SampError("insufficient data for group content header")
    return (
        _decode_ref(content, 0),
        _decode_ref(content, 6),
        _decode_ref(content, 12),
        bytes(content[18:]),
    )


def encode_group_members(member_pubkeys: list[Pubkey]) -> bytes:
    out = bytearray([len(member_pubkeys)])
    for pk in member_pubkeys:
        out.extend(pk)
    return bytes(out)


def decode_group_members(data: bytes) -> tuple[list[Pubkey], bytes]:
    if len(data) < 1:
        raise SampError("insufficient data for group members")
    count = data[0]
    expected = 1 + count * 32
    if len(data) < expected:
        raise SampError("insufficient data for group members")
    members: list[Pubkey] = []
    for i in range(count):
        start = 1 + i * 32
        members.append(pubkey_from_bytes(data[start : start + 32]))
    return members, bytes(data[expected:])
