from __future__ import annotations

import samp_crypto

from samp.wire import Remark

ENCRYPTED_OVERHEAD = 80  # ephemeral(32) + sealed_to(32) + auth_tag(16)


def sr25519_signing_scalar(seed: bytes) -> bytes:
    return samp_crypto.sr25519_signing_scalar(seed)


def public_from_seed(seed: bytes) -> bytes:
    return samp_crypto.public_from_seed(seed)


def encrypt(plaintext: bytes, recipient_pubkey: bytes, nonce: bytes, sender_seed: bytes) -> bytes:
    return samp_crypto.encrypt_content(plaintext, recipient_pubkey, nonce, sender_seed)


def decrypt(remark: Remark, signing_scalar: bytes) -> bytes:
    return samp_crypto.decrypt_content(remark.content, signing_scalar, remark.nonce)


def decrypt_as_sender(remark: Remark, sender_seed: bytes) -> bytes:
    return samp_crypto.decrypt_as_sender(remark.content, sender_seed, remark.nonce)


def compute_view_tag(sender_seed: bytes, recipient_pubkey: bytes, nonce: bytes) -> int:
    return samp_crypto.compute_view_tag(sender_seed, recipient_pubkey, nonce)


def check_view_tag(remark: Remark, signing_scalar: bytes) -> int:
    return samp_crypto.check_view_tag(signing_scalar, remark.content)


def unseal_recipient(remark: Remark, sender_seed: bytes) -> bytes:
    return samp_crypto.unseal_recipient(remark.content, sender_seed, remark.nonce)


def derive_group_ephemeral(sender_seed: bytes, nonce: bytes) -> bytes:
    return samp_crypto.derive_group_ephemeral(sender_seed, nonce)


def build_capsules(content_key: bytes, member_pubkeys: list[bytes], eph_scalar: bytes, nonce: bytes) -> bytes:
    return samp_crypto.build_capsules(content_key, member_pubkeys, eph_scalar, nonce)


def scan_capsules(data: bytes, eph_pubkey: bytes, my_scalar: bytes, nonce: bytes):
    return samp_crypto.scan_capsules(data, eph_pubkey, my_scalar, nonce)


def encrypt_for_group(plaintext: bytes, member_pubkeys: list[bytes], nonce: bytes, sender_seed: bytes) -> tuple[bytes, bytes, bytes]:
    return samp_crypto.encrypt_for_group(plaintext, member_pubkeys, nonce, sender_seed)


def decrypt_from_group(content: bytes, my_scalar: bytes, nonce: bytes, known_n: int | None = None) -> bytes:
    return samp_crypto.decrypt_from_group(content, my_scalar, nonce, known_n)
