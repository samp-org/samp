from __future__ import annotations

import pytest

import samp


def test_sr25519_sign_returns_64_bytes() -> None:
    seed = samp.Seed.from_bytes(bytes([0xAB] * 32))
    sig = samp.sr25519_sign(seed, b"test message")
    assert len(bytes(sig)) == 64


def test_sr25519_sign_differs_for_different_messages() -> None:
    seed = samp.Seed.from_bytes(bytes([0xAB] * 32))
    a = samp.sr25519_sign(seed, b"message one")
    b = samp.sr25519_sign(seed, b"message two")
    assert bytes(a) != bytes(b)


def test_derive_group_ephemeral_returns_bytes() -> None:
    seed = samp.Seed.from_bytes(bytes([0xAA] * 32))
    nonce = samp.nonce_from_bytes(bytes([0x01] * 12))
    result = samp.derive_group_ephemeral(seed, nonce)
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_build_capsules_returns_capsules() -> None:
    seed = samp.Seed.from_bytes(bytes([0xAA] * 32))
    nonce = samp.nonce_from_bytes(bytes([0x01] * 12))
    ck = samp.ContentKey.from_bytes(bytes([0xCC] * 32))
    recipient_pub = samp.public_from_seed(samp.Seed.from_bytes(bytes([0xBB] * 32)))
    eph = samp.derive_group_ephemeral(seed, nonce)
    capsules = samp.build_capsules(ck, [recipient_pub], eph, nonce)
    assert len(capsules) == 33


def test_scan_capsules_no_match() -> None:
    from samp.encryption import scan_capsules

    seed_a = samp.Seed.from_bytes(bytes([0xAA] * 32))
    seed_b = samp.Seed.from_bytes(bytes([0xBB] * 32))
    seed_c = samp.Seed.from_bytes(bytes([0xCC] * 32))
    nonce = samp.nonce_from_bytes(bytes([0x01] * 12))

    recipient_pub = samp.public_from_seed(seed_b)
    eph, capsules, _ct = samp.encrypt_for_group(
        samp.plaintext_from_bytes(b"msg"), [recipient_pub], nonce, seed_a
    )

    wrong_scalar = samp.sr25519_signing_scalar(seed_c)
    result = scan_capsules(bytes(capsules), eph, wrong_scalar, nonce)
    assert result is None


def test_decrypt_from_group_bad_content_raises() -> None:
    scalar = samp.sr25519_signing_scalar(samp.Seed.from_bytes(bytes([0xBB] * 32)))
    nonce = samp.nonce_from_bytes(bytes([0x01] * 12))
    with pytest.raises(samp.SampError):
        samp.decrypt_from_group(b"\x00" * 10, scalar, nonce)
