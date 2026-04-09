from __future__ import annotations

from typing import Optional

import samp_crypto

from samp.error import SampError
from samp.secret import ContentKey, Seed, ViewScalar
from samp.types import (
    Capsules,
    Ciphertext,
    EphPubkey,
    Nonce,
    Plaintext,
    Pubkey,
    ViewTag,
    capsules_from_bytes,
    ciphertext_from_bytes,
    eph_pubkey_from_bytes,
    plaintext_from_bytes,
    pubkey_from_bytes,
    view_tag_from_int,
)

ENCRYPTED_OVERHEAD = 80


def sr25519_signing_scalar(seed: Seed) -> ViewScalar:
    return ViewScalar.from_bytes(samp_crypto.sr25519_signing_scalar(seed.expose_secret()))


def public_from_seed(seed: Seed) -> Pubkey:
    return pubkey_from_bytes(samp_crypto.public_from_seed(seed.expose_secret()))


def encrypt(
    plaintext: Plaintext,
    recipient: Pubkey,
    nonce: Nonce,
    sender_seed: Seed,
) -> Ciphertext:
    return ciphertext_from_bytes(
        samp_crypto.encrypt_content(plaintext, recipient, nonce, sender_seed.expose_secret())
    )


def decrypt(
    ciphertext: Ciphertext,
    nonce: Nonce,
    signing_scalar: ViewScalar,
) -> Plaintext:
    return plaintext_from_bytes(
        samp_crypto.decrypt_content(ciphertext, signing_scalar.expose_secret(), nonce)
    )


def decrypt_as_sender(
    ciphertext: Ciphertext,
    nonce: Nonce,
    sender_seed: Seed,
) -> Plaintext:
    return plaintext_from_bytes(
        samp_crypto.decrypt_as_sender(ciphertext, sender_seed.expose_secret(), nonce)
    )


def compute_view_tag(sender_seed: Seed, recipient: Pubkey, nonce: Nonce) -> ViewTag:
    return view_tag_from_int(
        samp_crypto.compute_view_tag(sender_seed.expose_secret(), recipient, nonce)
    )


def check_view_tag(ciphertext: Ciphertext, signing_scalar: ViewScalar) -> ViewTag:
    return view_tag_from_int(samp_crypto.check_view_tag(signing_scalar.expose_secret(), ciphertext))


def unseal_recipient(ciphertext: Ciphertext, nonce: Nonce, sender_seed: Seed) -> Pubkey:
    return pubkey_from_bytes(
        samp_crypto.unseal_recipient(ciphertext, sender_seed.expose_secret(), nonce)
    )


def derive_group_ephemeral(sender_seed: Seed, nonce: Nonce) -> bytes:
    result: bytes = samp_crypto.derive_group_ephemeral(sender_seed.expose_secret(), nonce)
    return result


def build_capsules(
    content_key: ContentKey,
    member_pubkeys: list[Pubkey],
    eph_scalar: bytes,
    nonce: Nonce,
) -> Capsules:
    return capsules_from_bytes(
        samp_crypto.build_capsules(
            content_key.expose_secret(), list(member_pubkeys), eph_scalar, nonce
        )
    )


def scan_capsules(
    data: bytes,
    eph_pubkey: EphPubkey,
    my_scalar: ViewScalar,
    nonce: Nonce,
) -> Optional[tuple[int, ContentKey]]:
    result = samp_crypto.scan_capsules(data, eph_pubkey, my_scalar.expose_secret(), nonce)
    if result is None:
        return None
    idx, ck = result
    return int(idx), ContentKey.from_bytes(bytes(ck))


def encrypt_for_group(
    plaintext: Plaintext,
    member_pubkeys: list[Pubkey],
    nonce: Nonce,
    sender_seed: Seed,
) -> tuple[EphPubkey, Capsules, Ciphertext]:
    eph, caps, ct = samp_crypto.encrypt_for_group(
        plaintext, list(member_pubkeys), nonce, sender_seed.expose_secret()
    )
    return (
        eph_pubkey_from_bytes(eph),
        capsules_from_bytes(caps),
        ciphertext_from_bytes(ct),
    )


def decrypt_from_group(
    content: bytes,
    my_scalar: ViewScalar,
    nonce: Nonce,
    known_n: Optional[int] = None,
) -> Plaintext:
    try:
        return plaintext_from_bytes(
            samp_crypto.decrypt_from_group(content, my_scalar.expose_secret(), nonce, known_n)
        )
    except SampError:
        raise
    except Exception as e:
        raise SampError(f"decryption failed: {e}") from e
