from __future__ import annotations

import samp_crypto

ENCRYPTED_OVERHEAD = 80  # ephemeral(32) + sealed_to(32) + auth_tag(16)


def sr25519_signing_scalar(seed: bytes) -> bytes:
    """Derive the sr25519 signing scalar from a 32-byte seed."""
    return samp_crypto.sr25519_signing_scalar(seed)


def public_from_seed(seed: bytes) -> bytes:
    """Derive the sr25519 public key (Ristretto255 point) from a seed."""
    return samp_crypto.public_from_seed(seed)


def encrypt(plaintext: bytes, recipient_pubkey: bytes, nonce: bytes, sender_seed: bytes) -> bytes:
    """Encrypt plaintext for a recipient's sr25519 public key.

    Returns: eph_pubkey(32) || sealed_to(32) || ciphertext || auth_tag(16).
    """
    return samp_crypto.encrypt_content(plaintext, recipient_pubkey, nonce, sender_seed)


def decrypt(content: bytes, signing_scalar: bytes, nonce: bytes) -> bytes:
    """Decrypt as recipient using the sr25519 signing scalar."""
    return samp_crypto.decrypt_content(content, signing_scalar, nonce)


def decrypt_as_sender(content: bytes, sender_seed: bytes, nonce: bytes) -> bytes:
    """Decrypt as sender using the sender's seed (via sealed_to)."""
    return samp_crypto.decrypt_as_sender(content, sender_seed, nonce)


def compute_view_tag(sender_seed: bytes, recipient_pubkey: bytes, nonce: bytes) -> int:
    """Sender-side view tag computation."""
    return samp_crypto.compute_view_tag(sender_seed, recipient_pubkey, nonce)


def check_view_tag(signing_scalar: bytes, encrypted_content: bytes) -> int:
    """Recipient-side view tag check (Section 5.3)."""
    return samp_crypto.check_view_tag(signing_scalar, encrypted_content)


def unseal_recipient(encrypted_content: bytes, sender_seed: bytes, nonce: bytes) -> bytes:
    """Recover recipient pubkey from sealed_to (Section 5.5 step 3)."""
    return samp_crypto.unseal_recipient(encrypted_content, sender_seed, nonce)


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
