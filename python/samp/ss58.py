from __future__ import annotations

import hashlib

from samp.error import SampError
from samp.types import Pubkey, Ss58Address, Ss58Prefix, pubkey_from_bytes, ss58_prefix_from_int

_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode(pubkey: Pubkey, prefix: Ss58Prefix) -> Ss58Address:
    prefix_byte = int(prefix)
    payload = bytearray()
    payload.append(prefix_byte)
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
    if decoded[0] >= 64:
        raise SampError(f"ss58 prefix unsupported: {decoded[0]}")
    payload = decoded[:33]
    checksum = decoded[33:35]
    h = hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()
    if h[:2] != checksum:
        raise SampError("ss58 bad checksum")
    prefix = ss58_prefix_from_int(decoded[0])
    return Ss58Address.from_parts(address, pubkey_from_bytes(decoded[1:33]), prefix)


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
