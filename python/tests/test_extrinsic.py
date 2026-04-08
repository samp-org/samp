from __future__ import annotations

import json
from pathlib import Path

import pytest

from samp.extrinsic import (
    ChainParams,
    build_signed_extrinsic,
    extract_call,
    extract_signer,
)
from samp.scale import decode_compact, encode_compact

E2E = Path(__file__).resolve().parent.parent.parent / "e2e"

ALICE_PUBLIC_KEY = bytes.fromhex(
    "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
)
FIXED_SIGNATURE = b"\xab" * 64


def fixed_signer(_msg: bytes) -> bytes:
    return FIXED_SIGNATURE


def make_chain_params() -> ChainParams:
    return ChainParams(
        genesis_hash=b"\x11" * 32,
        spec_version=100,
        tx_version=1,
    )


def build_remark_args(remark: bytes) -> bytes:
    return encode_compact(len(remark)) + remark


def test_build_signed_extrinsic_round_trips_through_extract():
    args = build_remark_args(b"hello bob")
    ext = build_signed_extrinsic(
        pallet_idx=0,
        call_idx=7,
        call_args=args,
        public_key=ALICE_PUBLIC_KEY,
        sign=fixed_signer,
        nonce=0,
        chain_params=make_chain_params(),
    )

    signer = extract_signer(ext)
    assert signer == ALICE_PUBLIC_KEY

    extracted = extract_call(ext)
    assert extracted is not None
    assert extracted.pallet == 0
    assert extracted.call == 7
    assert extracted.args == args


def test_build_signed_extrinsic_starts_with_compact_length_prefix():
    ext = build_signed_extrinsic(
        0,
        7,
        build_remark_args(b"x"),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        0,
        make_chain_params(),
    )
    decoded = decode_compact(ext)
    assert decoded is not None
    declared_len, prefix_len = decoded
    assert declared_len + prefix_len == len(ext)


def test_build_signed_extrinsic_uses_immortal_era_byte():
    ext = build_signed_extrinsic(
        0,
        7,
        build_remark_args(b"x"),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        0,
        make_chain_params(),
    )
    _, prefix_len = decode_compact(ext)  # type: ignore[misc]
    payload = ext[prefix_len:]
    era_offset = 1 + 1 + 32 + 1 + 64
    assert payload[era_offset] == 0x00


def test_build_signed_extrinsic_different_nonces_produce_different_bytes():
    args = build_remark_args(b"x")
    cp = make_chain_params()
    a = build_signed_extrinsic(0, 7, args, ALICE_PUBLIC_KEY, fixed_signer, 0, cp)
    b = build_signed_extrinsic(0, 7, args, ALICE_PUBLIC_KEY, fixed_signer, 1, cp)
    assert a != b


def test_extract_signer_returns_none_for_unsigned_extrinsic():
    unsigned = bytes([0x10, 0x04, 0x03, 0x00, 0x00])
    assert extract_signer(unsigned) is None


def test_extract_call_returns_none_for_unsigned_extrinsic():
    unsigned = bytes([0x10, 0x04, 0x03, 0x00, 0x00])
    assert extract_call(unsigned) is None


def test_extract_signer_returns_none_for_empty_input():
    assert extract_signer(b"") is None


def test_build_signed_extrinsic_payload_above_256_bytes_uses_blake2_hash():
    big_remark = b"\xab" * 1024
    args = build_remark_args(big_remark)

    captured: list[int] = []

    def capturing_signer(msg: bytes) -> bytes:
        captured.append(len(msg))
        return FIXED_SIGNATURE

    ext = build_signed_extrinsic(
        0, 7, args, ALICE_PUBLIC_KEY, capturing_signer, 0, make_chain_params()
    )
    assert captured == [32]
    extracted = extract_call(ext)
    assert extracted is not None
    assert extracted.args == args


def test_build_signed_extrinsic_rejects_wrong_public_key_length():
    with pytest.raises(Exception):
        build_signed_extrinsic(
            0, 7, b"", b"\x00" * 31, fixed_signer, 0, make_chain_params()
        )


def test_matches_e2e_extrinsic_vectors_fixture():
    with open(E2E / "extrinsic-vectors.json") as f:
        vectors = json.load(f)
    for case in vectors["cases"]:
        public_key = bytes.fromhex(case["public_key"][2:])
        signature = bytes.fromhex(case["fixed_signature"][2:])
        call_args = bytes.fromhex(case["call_args"][2:])
        chain = ChainParams(
            genesis_hash=bytes.fromhex(case["chain_params"]["genesis_hash"][2:]),
            spec_version=case["chain_params"]["spec_version"],
            tx_version=case["chain_params"]["tx_version"],
        )

        built = build_signed_extrinsic(
            pallet_idx=case["pallet_idx"],
            call_idx=case["call_idx"],
            call_args=call_args,
            public_key=public_key,
            sign=lambda _msg, sig=signature: sig,
            nonce=case["nonce"],
            chain_params=chain,
        )

        expected = bytes.fromhex(case["expected_extrinsic"][2:])
        assert built == expected, f"case {case['label']} did not match fixture"
