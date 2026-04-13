from __future__ import annotations

import pytest

from samp import SampError, Ss58Address, pubkey_from_bytes, ss58_prefix_from_int


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
    with pytest.raises(SampError):
        ss58_prefix_from_int(64)
