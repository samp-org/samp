from __future__ import annotations

import json
from pathlib import Path

import pytest

from samp import SampError, Ss58Address, pubkey_from_bytes, ss58_prefix_from_int

VECTORS_PATH = Path(__file__).resolve().parent.parent.parent / "e2e" / "test-vectors.json"


def _alice_pk() -> bytes:
    return bytes.fromhex(
        "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
    )


def test_ss58_encode_decode_round_trip():
    pk = pubkey_from_bytes(_alice_pk())
    prefix = ss58_prefix_from_int(42)
    addr = Ss58Address.encode(pk, prefix)
    decoded = Ss58Address.parse(addr.as_str())
    assert bytes(decoded.pubkey()) == bytes(pk)
    assert int(decoded.prefix()) == 42


def test_ss58_encode_decode_prefix_0():
    pk = pubkey_from_bytes(_alice_pk())
    prefix = ss58_prefix_from_int(0)
    addr = Ss58Address.encode(pk, prefix)
    decoded = Ss58Address.parse(addr.as_str())
    assert bytes(decoded.pubkey()) == bytes(pk)
    assert int(decoded.prefix()) == 0


def test_ss58_decode_bad_checksum():
    pk = pubkey_from_bytes(_alice_pk())
    prefix = ss58_prefix_from_int(42)
    addr = Ss58Address.encode(pk, prefix)
    s = addr.as_str()
    corrupted = s[:-1] + ("B" if s[-1] != "B" else "A")
    with pytest.raises(SampError):
        Ss58Address.parse(corrupted)


def test_ss58_decode_too_short():
    with pytest.raises(SampError):
        Ss58Address.parse("5abc")


def test_ss58_decode_empty():
    with pytest.raises(SampError):
        Ss58Address.parse("")


def test_ss58_prefix_boundary():
    assert ss58_prefix_from_int(63) == 63
    assert ss58_prefix_from_int(64) == 64
    assert ss58_prefix_from_int(16_383) == 16_383
    with pytest.raises(SampError):
        ss58_prefix_from_int(16_384)


def test_ss58_vectors_round_trip_boundary_prefixes():
    vectors = json.loads(VECTORS_PATH.read_text())["ss58"]
    pk = pubkey_from_bytes(bytes.fromhex(vectors["pubkey"].removeprefix("0x")))
    for case in vectors["cases"]:
        prefix = ss58_prefix_from_int(case["prefix"])
        addr = Ss58Address.encode(pk, prefix)
        assert addr.as_str() == case["address"]
        decoded = Ss58Address.parse(case["address"])
        assert bytes(decoded.pubkey()) == bytes(pk)
        assert int(decoded.prefix()) == case["prefix"]


def test_ss58_decode_invalid_base58_char():
    with pytest.raises(SampError):
        Ss58Address.parse("0OIl" + "a" * 44)


def test_ss58_decode_high_unicode():
    with pytest.raises(SampError):
        Ss58Address.parse("\u0100" * 48)


def test_ss58_encode_empty_data():
    from samp.ss58 import _bs58_encode

    assert _bs58_encode(b"") == ""


def test_ss58_decode_rejects_two_byte_prefix_without_second_byte():
    from samp.ss58 import _decode_prefix

    with pytest.raises(SampError, match="too short"):
        _decode_prefix(bytes([0b0100_0000]))


def test_ss58_decode_rejects_reserved_high_bit_prefix():
    from samp.ss58 import _decode_prefix

    with pytest.raises(SampError, match="prefix unsupported"):
        _decode_prefix(bytes([0b1000_0000]))


def test_ss58_decode_rejects_two_byte_payload_missing_checksum_byte():
    from samp.ss58 import _bs58_encode

    raw = bytes([0b0100_0000, 0]) + bytes(32) + bytes([0])
    with pytest.raises(SampError, match="too short"):
        Ss58Address.parse(_bs58_encode(raw))


def test_ss58_decode_rejects_extra_payload_bytes():
    from samp.ss58 import _bs58_encode

    raw = bytes([42]) + bytes(32) + bytes(3)
    with pytest.raises(SampError, match="bad checksum"):
        Ss58Address.parse(_bs58_encode(raw))
