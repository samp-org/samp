from __future__ import annotations

import json
from pathlib import Path

import pytest

from samp import (
    call_args_from_bytes,
    call_idx_from_int,
    extrinsic_bytes_from_bytes,
    extrinsic_nonce_from_int,
    genesis_hash_from_bytes,
    pallet_idx_from_int,
    pubkey_from_bytes,
    spec_version_from_int,
    tx_version_from_int,
)
from samp.extrinsic import (
    ChainParams,
    build_signed_extrinsic,
    extract_call,
    extract_signer,
)
from samp.scale import decode_compact, encode_compact

E2E = Path(__file__).resolve().parent.parent.parent / "e2e"

ALICE_PUBLIC_KEY = pubkey_from_bytes(
    bytes.fromhex("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
)
FIXED_SIGNATURE = b"\xab" * 64


def fixed_signer(_msg: bytes) -> bytes:
    return FIXED_SIGNATURE


def make_chain_params() -> ChainParams:
    return ChainParams(
        genesis_hash=genesis_hash_from_bytes(b"\x11" * 32),
        spec_version=spec_version_from_int(100),
        tx_version=tx_version_from_int(1),
    )


def build_remark_args(remark: bytes) -> bytes:
    return encode_compact(len(remark)) + remark


def test_build_signed_extrinsic_round_trips_through_extract() -> None:
    args = build_remark_args(b"hello bob")
    ext = build_signed_extrinsic(
        pallet_idx=pallet_idx_from_int(0),
        call_idx=call_idx_from_int(7),
        call_args=call_args_from_bytes(args),
        public_key=ALICE_PUBLIC_KEY,
        sign=fixed_signer,
        nonce=extrinsic_nonce_from_int(0),
        chain_params=make_chain_params(),
    )

    signer = extract_signer(ext)
    assert signer == ALICE_PUBLIC_KEY

    extracted = extract_call(ext)
    assert extracted is not None
    assert int(extracted.pallet) == 0
    assert int(extracted.call) == 7
    assert bytes(extracted.args) == args


def test_build_signed_extrinsic_starts_with_compact_length_prefix() -> None:
    ext = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        call_args_from_bytes(build_remark_args(b"x")),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(0),
        make_chain_params(),
    )
    decoded = decode_compact(ext)
    assert decoded is not None
    declared_len, prefix_len = decoded
    assert declared_len + prefix_len == len(ext)


def test_build_signed_extrinsic_uses_immortal_era_byte() -> None:
    ext = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        call_args_from_bytes(build_remark_args(b"x")),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(0),
        make_chain_params(),
    )
    decoded = decode_compact(ext)
    assert decoded is not None
    _, prefix_len = decoded
    payload = ext[prefix_len:]
    era_offset = 1 + 1 + 32 + 1 + 64
    assert payload[era_offset] == 0x00


def test_build_signed_extrinsic_different_nonces_produce_different_bytes() -> None:
    args = call_args_from_bytes(build_remark_args(b"x"))
    cp = make_chain_params()
    a = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        args,
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(0),
        cp,
    )
    b = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        args,
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(1),
        cp,
    )
    assert a != b


def test_extract_signer_returns_none_for_unsigned_extrinsic() -> None:
    unsigned = extrinsic_bytes_from_bytes(bytes([0x10, 0x04, 0x03, 0x00, 0x00]))
    assert extract_signer(unsigned) is None


def test_extract_call_returns_none_for_unsigned_extrinsic() -> None:
    unsigned = extrinsic_bytes_from_bytes(bytes([0x10, 0x04, 0x03, 0x00, 0x00]))
    assert extract_call(unsigned) is None


def test_extract_signer_returns_none_for_empty_input() -> None:
    assert extract_signer(extrinsic_bytes_from_bytes(b"")) is None


def test_build_signed_extrinsic_payload_above_256_bytes_uses_blake2_hash() -> None:
    big_remark = b"\xab" * 1024
    args = build_remark_args(big_remark)

    captured: list[int] = []

    def capturing_signer(msg: bytes) -> bytes:
        captured.append(len(msg))
        return FIXED_SIGNATURE

    ext = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        call_args_from_bytes(args),
        ALICE_PUBLIC_KEY,
        capturing_signer,
        extrinsic_nonce_from_int(0),
        make_chain_params(),
    )
    assert captured == [32]
    extracted = extract_call(ext)
    assert extracted is not None
    assert bytes(extracted.args) == args


def test_build_signed_extrinsic_rejects_wrong_public_key_length() -> None:
    from samp.error import SampError

    with pytest.raises(SampError):
        build_signed_extrinsic(
            pallet_idx_from_int(0),
            call_idx_from_int(7),
            call_args_from_bytes(b""),
            pubkey_from_bytes(b"\x00" * 31),
            fixed_signer,
            extrinsic_nonce_from_int(0),
            make_chain_params(),
        )


def test_matches_e2e_extrinsic_vectors_fixture() -> None:
    with open(E2E / "extrinsic-vectors.json") as f:
        vectors = json.load(f)
    for case in vectors["cases"]:
        public_key = pubkey_from_bytes(bytes.fromhex(case["public_key"][2:]))
        signature = bytes.fromhex(case["fixed_signature"][2:])
        call_args = call_args_from_bytes(bytes.fromhex(case["call_args"][2:]))
        chain = ChainParams(
            genesis_hash=genesis_hash_from_bytes(
                bytes.fromhex(case["chain_params"]["genesis_hash"][2:])
            ),
            spec_version=spec_version_from_int(case["chain_params"]["spec_version"]),
            tx_version=tx_version_from_int(case["chain_params"]["tx_version"]),
        )

        def signer(_msg: bytes, sig: bytes = signature) -> bytes:
            return sig

        built = build_signed_extrinsic(
            pallet_idx=pallet_idx_from_int(case["pallet_idx"]),
            call_idx=call_idx_from_int(case["call_idx"]),
            call_args=call_args,
            public_key=public_key,
            sign=signer,
            nonce=extrinsic_nonce_from_int(case["nonce"]),
            chain_params=chain,
        )

        expected = bytes.fromhex(case["expected_extrinsic"][2:])
        assert built == expected, f"case {case['label']} did not match fixture"


def test_extract_call_returns_none_for_empty_input() -> None:
    assert extract_call(extrinsic_bytes_from_bytes(b"")) is None


def test_extract_call_returns_none_for_truncated_payload() -> None:
    ext = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        call_args_from_bytes(build_remark_args(b"x")),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(0),
        make_chain_params(),
    )
    decoded = decode_compact(ext)
    assert decoded is not None
    _, prefix_len = decoded
    truncated = ext[:prefix_len + 50]
    assert extract_call(extrinsic_bytes_from_bytes(truncated)) is None


def test_extract_call_non_immortal_era() -> None:
    ext = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        call_args_from_bytes(build_remark_args(b"hello")),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(0),
        make_chain_params(),
    )
    decoded = decode_compact(ext)
    assert decoded is not None
    _, prefix_len = decoded
    payload = bytearray(ext[prefix_len:])
    from samp.extrinsic import SIGNED_HEADER_LEN
    payload[SIGNED_HEADER_LEN] = 0x01
    modified = ext[:prefix_len] + bytes(payload)
    result = extract_call(extrinsic_bytes_from_bytes(modified))
    assert result is not None


def test_extract_call_truncated_at_nonce() -> None:
    ext = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        call_args_from_bytes(build_remark_args(b"x")),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(0),
        make_chain_params(),
    )
    decoded = decode_compact(ext)
    assert decoded is not None
    _, prefix_len = decoded
    payload = bytearray(ext[prefix_len:])
    from samp.extrinsic import SIGNED_HEADER_LEN
    truncated_payload = bytes(payload[:SIGNED_HEADER_LEN + 1])
    length_prefix = encode_compact(len(truncated_payload))
    result = extract_call(extrinsic_bytes_from_bytes(length_prefix + truncated_payload))
    assert result is None


def test_extract_call_truncated_at_tip() -> None:
    ext = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        call_args_from_bytes(build_remark_args(b"x")),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(0),
        make_chain_params(),
    )
    decoded = decode_compact(ext)
    assert decoded is not None
    _, prefix_len = decoded
    payload = bytearray(ext[prefix_len:])
    from samp.extrinsic import SIGNED_HEADER_LEN
    truncated_payload = bytes(payload[:SIGNED_HEADER_LEN + 2])
    length_prefix = encode_compact(len(truncated_payload))
    result = extract_call(extrinsic_bytes_from_bytes(length_prefix + truncated_payload))
    assert result is None


def test_extract_call_truncated_at_pallet_call() -> None:
    ext = build_signed_extrinsic(
        pallet_idx_from_int(0),
        call_idx_from_int(7),
        call_args_from_bytes(build_remark_args(b"x")),
        ALICE_PUBLIC_KEY,
        fixed_signer,
        extrinsic_nonce_from_int(0),
        make_chain_params(),
    )
    decoded = decode_compact(ext)
    assert decoded is not None
    _, prefix_len = decoded
    payload = bytearray(ext[prefix_len:])
    from samp.extrinsic import SIGNED_HEADER_LEN
    truncated_payload = bytes(payload[:SIGNED_HEADER_LEN + 4])
    length_prefix = encode_compact(len(truncated_payload))
    result = extract_call(extrinsic_bytes_from_bytes(length_prefix + truncated_payload))
    assert result is None
