from __future__ import annotations

import json
from pathlib import Path

import pytest

from samp.scale import decode_bytes, decode_compact, encode_compact

E2E = Path(__file__).resolve().parent.parent.parent / "e2e"


def test_compact_mode_zero_at_lower_bound():
    assert encode_compact(0) == b"\x00"
    assert decode_compact(b"\x00") == (0, 1)


def test_compact_mode_zero_at_upper_bound():
    assert encode_compact(63) == b"\xfc"
    assert decode_compact(b"\xfc") == (63, 1)


def test_compact_mode_one_at_lower_bound():
    assert encode_compact(64) == b"\x01\x01"
    assert decode_compact(b"\x01\x01") == (64, 2)


def test_compact_mode_one_at_upper_bound():
    encoded = encode_compact(16_383)
    assert decode_compact(encoded) == (16_383, 2)


def test_compact_mode_two_at_lower_bound():
    encoded = encode_compact(16_384)
    assert decode_compact(encoded) == (16_384, 4)


def test_compact_mode_two_at_upper_bound():
    encoded = encode_compact((1 << 30) - 1)
    assert decode_compact(encoded) == ((1 << 30) - 1, 4)


def test_compact_big_int_mode_at_2_pow_30():
    encoded = encode_compact(1 << 30)
    decoded = decode_compact(encoded)
    assert decoded is not None
    assert decoded[0] == 1 << 30


def test_compact_big_int_mode_u64_max():
    encoded = encode_compact((1 << 64) - 1)
    decoded = decode_compact(encoded)
    assert decoded is not None
    assert decoded[0] == (1 << 64) - 1


@pytest.mark.parametrize(
    "value",
    [0, 1, 63, 64, 100, 16_383, 16_384, 1 << 20, (1 << 30) - 1, 1 << 30, 1 << 32, (1 << 64) - 1],
)
def test_compact_round_trip(value: int):
    encoded = encode_compact(value)
    decoded = decode_compact(encoded)
    assert decoded is not None
    assert decoded[0] == value


def test_decode_compact_returns_none_on_empty_input():
    assert decode_compact(b"") is None


def test_decode_compact_returns_none_on_truncated_two_byte_mode():
    assert decode_compact(b"\x01") is None


def test_decode_compact_returns_none_on_truncated_four_byte_mode():
    assert decode_compact(b"\x02\x00\x00") is None


def test_decode_compact_returns_none_on_truncated_big_int_mode():
    assert decode_compact(b"\x03\x01") is None


def test_decode_bytes_extracts_payload_after_compact_length():
    wire = encode_compact(5) + b"hello"
    result = decode_bytes(wire)
    assert result == (b"hello", 6)


def test_decode_bytes_returns_none_when_payload_truncated():
    wire = encode_compact(10) + b"only5"
    assert decode_bytes(wire) is None


def test_matches_e2e_scale_vectors_fixture():
    with open(E2E / "scale-vectors.json") as f:
        vectors = json.load(f)
    for case in vectors["compact"]:
        value = int(case["value"])
        expected = bytes.fromhex(case["encoded"][2:])
        assert encode_compact(value) == expected, f"encode mismatch for {value}"
        decoded = decode_compact(expected)
        assert decoded is not None
        assert decoded[0] == value
        assert decoded[1] == case["consumed"]


def test_encode_compact_negative_raises():
    with pytest.raises(ValueError):
        encode_compact(-1)


def test_decode_bytes_returns_none_on_empty():
    assert decode_bytes(b"") is None
