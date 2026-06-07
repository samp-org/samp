from __future__ import annotations

import hashlib

from samp.error import SampError
from samp.types import Pubkey, Ss58Address, Ss58Prefix, pubkey_from_bytes, ss58_prefix_from_int

_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode(pubkey: Pubkey, prefix: Ss58Prefix) -> Ss58Address:
    payload = bytearray()
    payload.extend(_encode_prefix(int(prefix)))
    payload.extend(pubkey)
    h = hashlib.blake2b(b"SS58PRE" + bytes(payload), digest_size=64).digest()
    payload.extend(h[:2])
    return Ss58Address.from_parts(_bs58_encode(bytes(payload)), pubkey, prefix)


def decode(address: str) -> Ss58Address:
    decoded = _bs58_decode(address)
    if decoded is None:
        raise SampError("ss58 invalid base58")
    if len(decoded) < 35:
        raise SampError("ss58 too short")
    prefix_value, prefix_len = _decode_prefix(decoded)
    pubkey_end = prefix_len + 32
    if len(decoded) < pubkey_end + 2:
        raise SampError("ss58 too short")
    if len(decoded) != pubkey_end + 2:
        raise SampError("ss58 bad checksum")
    payload = decoded[:pubkey_end]
    checksum = decoded[pubkey_end : pubkey_end + 2]
    h = hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()
    if h[:2] != checksum:
        raise SampError("ss58 bad checksum")
    prefix = ss58_prefix_from_int(prefix_value)
    return Ss58Address.from_parts(address, pubkey_from_bytes(decoded[prefix_len:pubkey_end]), prefix)


def _encode_prefix(prefix: int) -> bytes:
    if prefix < 64:
        return bytes([prefix])
    return bytes(
        [
            ((prefix & 0b0000_0000_1111_1100) >> 2) | 0b0100_0000,
            (prefix >> 8) | ((prefix & 0b0000_0000_0000_0011) << 6),
        ]
    )


def _decode_prefix(decoded: bytes) -> tuple[int, int]:
    first = decoded[0]
    if first & 0b1000_0000 != 0:
        raise SampError(f"ss58 prefix unsupported: {first}")
    if first & 0b0100_0000 == 0:
        return first, 1
    if len(decoded) < 2:
        raise SampError("ss58 too short")
    second = decoded[1]
    prefix = ((first & 0b0011_1111) << 2) | (second >> 6) | ((second & 0b0011_1111) << 8)
    return prefix, 2


def _bs58_decode(s: str) -> bytes | None:
    out = bytearray([0])
    for ch in s:
        code = ord(ch)
        if code > 255:
            return None
        idx = _ALPHABET.find(code)
        if idx < 0:
            return None
        carry = idx
        for i in range(len(out)):
            carry += out[i] * 58
            out[i] = carry % 256
            carry //= 256
        while carry > 0:
            out.append(carry % 256)
            carry //= 256
    for ch in s:
        if ch == "1":
            out.append(0)
        else:
            break
    out.reverse()
    return bytes(out)


def _bs58_encode(data: bytes) -> str:
    if not data:
        return ""
    digits = [0]
    for byte in data:
        carry = byte
        for i in range(len(digits)):
            carry += digits[i] * 256
            digits[i] = carry % 58
            carry //= 58
        while carry > 0:
            digits.append(carry % 58)
            carry //= 58
    result: list[str] = []
    for b in data:
        if b == 0:
            result.append(chr(_ALPHABET[0]))
        else:
            break
    for d in reversed(digits):
        result.append(chr(_ALPHABET[d]))
    return "".join(result)
