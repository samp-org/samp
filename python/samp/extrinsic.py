from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable

from samp.scale import decode_compact, encode_compact

EXT_VERSION_SIGNED = 0x84
ADDR_TYPE_ID = 0x00
SIG_TYPE_SR25519 = 0x01
ERA_IMMORTAL = 0x00
METADATA_HASH_DISABLED = 0x00
SIGNED_HEADER_LEN = 99
MIN_SIGNED_EXTRINSIC = 103
MIN_SIGNER_PAYLOAD = 34


class ExtrinsicError(Exception):
    pass


@dataclass(frozen=True)
class ChainParams:
    genesis_hash: bytes
    spec_version: int
    tx_version: int


@dataclass(frozen=True)
class ExtractedCall:
    pallet: int
    call: int
    args: bytes


def build_signed_extrinsic(
    pallet_idx: int,
    call_idx: int,
    call_args: bytes,
    public_key: bytes,
    sign: Callable[[bytes], bytes],
    nonce: int,
    chain_params: ChainParams,
) -> bytes:
    if len(public_key) != 32:
        raise ExtrinsicError(f"public_key must be 32 bytes, got {len(public_key)}")
    if len(chain_params.genesis_hash) != 32:
        raise ExtrinsicError(
            f"genesis_hash must be 32 bytes, got {len(chain_params.genesis_hash)}"
        )

    call_data = bytes([pallet_idx, call_idx]) + call_args
    tip = bytes([0])

    signing_payload = (
        call_data
        + bytes([ERA_IMMORTAL])
        + encode_compact(nonce)
        + tip
        + bytes([METADATA_HASH_DISABLED])
        + chain_params.spec_version.to_bytes(4, "little")
        + chain_params.tx_version.to_bytes(4, "little")
        + chain_params.genesis_hash
        + chain_params.genesis_hash
        + bytes([0x00])
    )

    if len(signing_payload) > 256:
        to_sign = hashlib.blake2b(signing_payload, digest_size=32).digest()
    else:
        to_sign = signing_payload

    signature = sign(to_sign)
    if len(signature) != 64:
        raise ExtrinsicError(f"signature must be 64 bytes, got {len(signature)}")

    extrinsic_payload = (
        bytes([EXT_VERSION_SIGNED, ADDR_TYPE_ID])
        + public_key
        + bytes([SIG_TYPE_SR25519])
        + signature
        + bytes([ERA_IMMORTAL])
        + encode_compact(nonce)
        + tip
        + bytes([METADATA_HASH_DISABLED])
        + call_data
    )

    return encode_compact(len(extrinsic_payload)) + extrinsic_payload


def extract_signer(extrinsic_bytes: bytes) -> bytes | None:
    decoded = decode_compact(extrinsic_bytes)
    if decoded is None:
        return None
    _, prefix_len = decoded
    payload = extrinsic_bytes[prefix_len:]
    if (
        len(payload) < MIN_SIGNER_PAYLOAD
        or payload[0] & 0x80 == 0
        or payload[1] != ADDR_TYPE_ID
    ):
        return None
    return payload[2:34]


def extract_call(extrinsic_bytes: bytes) -> ExtractedCall | None:
    decoded = decode_compact(extrinsic_bytes)
    if decoded is None:
        return None
    _, prefix_len = decoded
    payload = extrinsic_bytes[prefix_len:]

    if len(payload) < MIN_SIGNED_EXTRINSIC or payload[0] & 0x80 == 0:
        return None

    offset = SIGNED_HEADER_LEN
    if offset >= len(payload):
        return None
    if payload[offset] != 0x00:
        offset += 2
    else:
        offset += 1

    nonce = decode_compact(payload[offset:])
    if nonce is None:
        return None
    offset += nonce[1]

    tip = decode_compact(payload[offset:])
    if tip is None:
        return None
    offset += tip[1]

    offset += 1

    if offset + 2 > len(payload):
        return None
    pallet = payload[offset]
    call = payload[offset + 1]
    offset += 2

    if offset > len(payload):
        return None

    return ExtractedCall(pallet=pallet, call=call, args=payload[offset:])
