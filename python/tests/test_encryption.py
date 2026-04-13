from __future__ import annotations

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
