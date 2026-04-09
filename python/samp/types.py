from __future__ import annotations

from dataclasses import dataclass
from typing import NewType

from samp.error import SampError

CAPSULE_SIZE = 33
CHANNEL_NAME_MAX = 32
CHANNEL_DESC_MAX = 128


Pubkey = NewType("Pubkey", bytes)
EphPubkey = NewType("EphPubkey", bytes)
GenesisHash = NewType("GenesisHash", bytes)
Signature = NewType("Signature", bytes)
Nonce = NewType("Nonce", bytes)
Plaintext = NewType("Plaintext", bytes)
Ciphertext = NewType("Ciphertext", bytes)
Capsules = NewType("Capsules", bytes)
RemarkBytes = NewType("RemarkBytes", bytes)
ExtrinsicBytes = NewType("ExtrinsicBytes", bytes)
CallArgs = NewType("CallArgs", bytes)

BlockNumber = NewType("BlockNumber", int)
ExtIndex = NewType("ExtIndex", int)
ExtrinsicNonce = NewType("ExtrinsicNonce", int)
SpecVersion = NewType("SpecVersion", int)
TxVersion = NewType("TxVersion", int)
PalletIdx = NewType("PalletIdx", int)
CallIdx = NewType("CallIdx", int)
ViewTag = NewType("ViewTag", int)
Ss58Prefix = NewType("Ss58Prefix", int)


def pubkey_from_bytes(b: bytes) -> Pubkey:
    if len(b) != 32:
        raise SampError(f"pubkey must be 32 bytes, got {len(b)}")
    return Pubkey(bytes(b))


def pubkey_zero() -> Pubkey:
    return Pubkey(bytes(32))


def eph_pubkey_from_bytes(b: bytes) -> EphPubkey:
    if len(b) != 32:
        raise SampError(f"eph_pubkey must be 32 bytes, got {len(b)}")
    return EphPubkey(bytes(b))


def genesis_hash_from_bytes(b: bytes) -> GenesisHash:
    if len(b) != 32:
        raise SampError(f"genesis_hash must be 32 bytes, got {len(b)}")
    return GenesisHash(bytes(b))


def signature_from_bytes(b: bytes) -> Signature:
    if len(b) != 64:
        raise SampError(f"signature must be 64 bytes, got {len(b)}")
    return Signature(bytes(b))


def nonce_from_bytes(b: bytes) -> Nonce:
    if len(b) != 12:
        raise SampError(f"nonce must be 12 bytes, got {len(b)}")
    return Nonce(bytes(b))


def plaintext_from_bytes(b: bytes) -> Plaintext:
    return Plaintext(bytes(b))


def ciphertext_from_bytes(b: bytes) -> Ciphertext:
    return Ciphertext(bytes(b))


def capsules_from_bytes(b: bytes) -> Capsules:
    if len(b) % CAPSULE_SIZE != 0:
        raise SampError(f"capsule length not multiple of {CAPSULE_SIZE}: {len(b)}")
    return Capsules(bytes(b))


def capsules_count(c: Capsules) -> int:
    return len(c) // CAPSULE_SIZE


def remark_bytes_from_bytes(b: bytes) -> RemarkBytes:
    return RemarkBytes(bytes(b))


def extrinsic_bytes_from_bytes(b: bytes) -> ExtrinsicBytes:
    return ExtrinsicBytes(bytes(b))


def call_args_from_bytes(b: bytes) -> CallArgs:
    return CallArgs(bytes(b))


def block_number_from_int(n: int) -> BlockNumber:
    if not 0 <= n <= 0xFFFF_FFFF:
        raise SampError(f"block number out of u32 range: {n}")
    return BlockNumber(n)


def ext_index_from_int(n: int) -> ExtIndex:
    if not 0 <= n <= 0xFFFF:
        raise SampError(f"ext index out of u16 range: {n}")
    return ExtIndex(n)


def extrinsic_nonce_from_int(n: int) -> ExtrinsicNonce:
    if not 0 <= n <= 0xFFFF_FFFF:
        raise SampError(f"extrinsic nonce out of u32 range: {n}")
    return ExtrinsicNonce(n)


def spec_version_from_int(n: int) -> SpecVersion:
    if not 0 <= n <= 0xFFFF_FFFF:
        raise SampError(f"spec version out of u32 range: {n}")
    return SpecVersion(n)


def tx_version_from_int(n: int) -> TxVersion:
    if not 0 <= n <= 0xFFFF_FFFF:
        raise SampError(f"tx version out of u32 range: {n}")
    return TxVersion(n)


def pallet_idx_from_int(n: int) -> PalletIdx:
    if not 0 <= n <= 0xFF:
        raise SampError(f"pallet idx out of u8 range: {n}")
    return PalletIdx(n)


def call_idx_from_int(n: int) -> CallIdx:
    if not 0 <= n <= 0xFF:
        raise SampError(f"call idx out of u8 range: {n}")
    return CallIdx(n)


def view_tag_from_int(n: int) -> ViewTag:
    if not 0 <= n <= 0xFF:
        raise SampError(f"view tag out of u8 range: {n}")
    return ViewTag(n)


SS58_PREFIX_SUBSTRATE_GENERIC = 42
SS58_PREFIX_POLKADOT = 0
SS58_PREFIX_KUSAMA = 2


def ss58_prefix_from_int(n: int) -> Ss58Prefix:
    if not 0 <= n <= 63:
        raise SampError(f"ss58 prefix unsupported: {n}")
    return Ss58Prefix(n)


@dataclass(frozen=True)
class BlockRef:
    number: BlockNumber
    index: ExtIndex

    @classmethod
    def of(cls, number: BlockNumber, index: ExtIndex) -> "BlockRef":
        return cls(number, index)

    @classmethod
    def from_parts(cls, number: int, index: int) -> "BlockRef":
        return cls(block_number_from_int(number), ext_index_from_int(index))

    @classmethod
    def zero(cls) -> "BlockRef":
        return cls(BlockNumber(0), ExtIndex(0))

    def is_zero(self) -> bool:
        return self.number == 0 and self.index == 0

    def __str__(self) -> str:
        return f"#{int(self.number)}.{int(self.index)}"


@dataclass(frozen=True)
class ChannelName:
    _value: str

    @classmethod
    def parse(cls, s: str) -> "ChannelName":
        n = len(s.encode("utf-8"))
        if n == 0 or n > CHANNEL_NAME_MAX:
            raise SampError(f"channel name must be 1-{CHANNEL_NAME_MAX} bytes, got {n}")
        return cls(s)

    def as_str(self) -> str:
        return self._value

    def byte_length(self) -> int:
        return len(self._value.encode("utf-8"))


@dataclass(frozen=True)
class ChannelDescription:
    _value: str

    @classmethod
    def parse(cls, s: str) -> "ChannelDescription":
        n = len(s.encode("utf-8"))
        if n > CHANNEL_DESC_MAX:
            raise SampError(f"channel description must be 0-{CHANNEL_DESC_MAX} bytes, got {n}")
        return cls(s)

    def as_str(self) -> str:
        return self._value

    def byte_length(self) -> int:
        return len(self._value.encode("utf-8"))


@dataclass(frozen=True)
class Ss58Address:
    _address: str
    _pubkey: Pubkey
    _prefix: Ss58Prefix

    @classmethod
    def from_parts(cls, address: str, pubkey: Pubkey, prefix: Ss58Prefix) -> "Ss58Address":
        return cls(address, pubkey, prefix)

    @classmethod
    def parse(cls, s: str) -> "Ss58Address":
        from samp.ss58 import decode as _ss58_decode

        return _ss58_decode(s)

    @classmethod
    def encode(cls, pubkey: Pubkey, prefix: Ss58Prefix) -> "Ss58Address":
        from samp.ss58 import encode as _ss58_encode

        return _ss58_encode(pubkey, prefix)

    def as_str(self) -> str:
        return self._address

    def pubkey(self) -> Pubkey:
        return self._pubkey

    def prefix(self) -> Ss58Prefix:
        return self._prefix

    def __str__(self) -> str:
        return self._address
