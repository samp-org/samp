from __future__ import annotations

import pytest

from samp import (
    SampError,
    Seed,
    encrypt,
    nonce_from_bytes,
    plaintext_from_bytes,
    sr25519_signing_scalar,
)
from samp.encryption import (
    decrypt,
    decrypt_as_sender,
    decrypt_from_group,
    encrypt_for_group,
    public_from_seed,
    unseal_recipient,
)

SENDER_SEED = Seed.from_bytes(bytes([0xAA] * 32))
RECIPIENT_SEED = Seed.from_bytes(bytes([0xBB] * 32))
NONCE = nonce_from_bytes(bytes([0x01] * 12))


def test_decrypt_wrong_key_fails() -> None:
    recipient_pub = public_from_seed(RECIPIENT_SEED)
    pt = plaintext_from_bytes(b"hello world")
    ct = encrypt(pt, recipient_pub, NONCE, SENDER_SEED)

    wrong_scalar = sr25519_signing_scalar(SENDER_SEED)
    with pytest.raises((SampError, Exception)):
        decrypt(ct, NONCE, wrong_scalar)


def test_encrypt_decrypt_as_sender() -> None:
    recipient_pub = public_from_seed(RECIPIENT_SEED)
    pt = plaintext_from_bytes(b"roundtrip test")
    ct = encrypt(pt, recipient_pub, NONCE, SENDER_SEED)

    recovered = decrypt_as_sender(ct, NONCE, SENDER_SEED)
    assert bytes(recovered) == b"roundtrip test"


def test_unseal_recipient() -> None:
    recipient_pub = public_from_seed(RECIPIENT_SEED)
    pt = plaintext_from_bytes(b"sealed")
    ct = encrypt(pt, recipient_pub, NONCE, SENDER_SEED)

    unsealed = unseal_recipient(ct, NONCE, SENDER_SEED)
    assert bytes(unsealed) == bytes(recipient_pub)


def test_group_encrypt_single_member() -> None:
    recipient_pub = public_from_seed(RECIPIENT_SEED)
    recipient_scalar = sr25519_signing_scalar(RECIPIENT_SEED)
    pt = plaintext_from_bytes(b"group msg")

    eph, capsules, ct = encrypt_for_group(pt, [recipient_pub], NONCE, SENDER_SEED)

    content = bytes(eph) + bytes(capsules) + bytes(ct)
    recovered = decrypt_from_group(content, recipient_scalar, NONCE, known_n=1)
    assert bytes(recovered) == b"group msg"


def test_check_view_tag_direct() -> None:
    from samp.encryption import check_view_tag, compute_view_tag

    recipient_pub = public_from_seed(RECIPIENT_SEED)
    recipient_scalar = sr25519_signing_scalar(RECIPIENT_SEED)
    pt = plaintext_from_bytes(b"view tag test")
    nonce = nonce_from_bytes(bytes([0x02] * 12))

    sender_tag = compute_view_tag(SENDER_SEED, recipient_pub, nonce)
    ct = encrypt(pt, recipient_pub, nonce, SENDER_SEED)
    recipient_tag = check_view_tag(ct, recipient_scalar)
    assert int(sender_tag) == int(recipient_tag)


def test_group_decrypt_from_group_auto_n() -> None:
    recipient_pub = public_from_seed(RECIPIENT_SEED)
    recipient_scalar = sr25519_signing_scalar(RECIPIENT_SEED)
    pt = plaintext_from_bytes(b"auto n group msg")

    eph, capsules, ct = encrypt_for_group(pt, [recipient_pub], NONCE, SENDER_SEED)

    content = bytes(eph) + bytes(capsules) + bytes(ct)
    recovered = decrypt_from_group(content, recipient_scalar, NONCE)
    assert bytes(recovered) == b"auto n group msg"
