from __future__ import annotations

import pytest

from samp import (
    ChannelCreateRemark,
    ChannelDescription,
    ChannelName,
    SampError,
    decode_remark,
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
