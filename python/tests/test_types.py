from __future__ import annotations

import pytest

from samp import ChannelDescription, ChannelName, SampError, Seed


def test_seed_repr_redacted() -> None:
    seed = Seed.from_bytes(bytes(32))
    assert "REDACTED" in repr(seed)


def test_seed_wrong_length_raises() -> None:
    with pytest.raises(SampError):
        Seed.from_bytes(b"short")


def test_channel_name_parse_too_long() -> None:
    with pytest.raises(SampError):
        ChannelName.parse("x" * 33)


def test_channel_name_parse_valid() -> None:
    name = ChannelName.parse("test")
    assert name.as_str() == "test"


def test_channel_desc_parse_too_long() -> None:
    with pytest.raises(SampError):
        ChannelDescription.parse("x" * 129)
