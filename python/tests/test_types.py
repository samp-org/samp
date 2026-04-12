from __future__ import annotations

import pytest

from samp import ChannelDescription, ChannelName, SampError, Seed


def test_seed_repr_redacted() -> None:
    seed = Seed.from_bytes(bytes(32))
    assert "REDACTED" in repr(seed)


def test_seed_wrong_length_raises() -> None:
    with pytest.raises(SampError):
        Seed.from_bytes(b"short")


def test_channel_name_parse_too_long() -> None:
    with pytest.raises(SampError):
        ChannelName.parse("x" * 33)


def test_channel_name_parse_valid() -> None:
    name = ChannelName.parse("test")
    assert name.as_str() == "test"


def test_channel_desc_parse_too_long() -> None:
    with pytest.raises(SampError):
        ChannelDescription.parse("x" * 129)


# --- secret.py: ViewScalar ---


def test_view_scalar_repr_redacted() -> None:
    from samp import ViewScalar

    vs = ViewScalar.from_bytes(bytes(32))
    assert "REDACTED" in repr(vs)


def test_view_scalar_wrong_length() -> None:
    from samp import ViewScalar

    with pytest.raises(SampError):
        ViewScalar.from_bytes(b"short")


# --- secret.py: ContentKey ---


def test_content_key_repr_redacted() -> None:
    from samp import ContentKey

    ck = ContentKey.from_bytes(bytes(32))
    assert "REDACTED" in repr(ck)


def test_content_key_wrong_length() -> None:
    from samp import ContentKey

    with pytest.raises(SampError):
        ContentKey.from_bytes(b"short")


# --- types.py: constructors ---


def test_view_tag_from_int() -> None:
    from samp import view_tag_from_int

    vt = view_tag_from_int(42)
    assert int(vt) == 42


def test_view_tag_from_int_out_of_range() -> None:
    from samp import view_tag_from_int

    with pytest.raises(SampError):
        view_tag_from_int(256)


def test_eph_pubkey_from_bytes() -> None:
    from samp import eph_pubkey_from_bytes

    ep = eph_pubkey_from_bytes(bytes(32))
    assert len(ep) == 32


def test_eph_pubkey_from_bytes_wrong_length() -> None:
    from samp import eph_pubkey_from_bytes

    with pytest.raises(SampError):
        eph_pubkey_from_bytes(bytes(10))


def test_ciphertext_from_bytes() -> None:
    from samp import ciphertext_from_bytes

    ct = ciphertext_from_bytes(bytes(80))
    assert len(ct) == 80


def test_plaintext_from_bytes() -> None:
    from samp import plaintext_from_bytes

    pt = plaintext_from_bytes(b"hello")
    assert bytes(pt) == b"hello"


def test_nonce_from_bytes() -> None:
    from samp import nonce_from_bytes

    n = nonce_from_bytes(bytes(12))
    assert len(n) == 12


def test_nonce_from_bytes_wrong_length() -> None:
    from samp import nonce_from_bytes

    with pytest.raises(SampError):
        nonce_from_bytes(bytes(5))


def test_signature_from_bytes() -> None:
    from samp import signature_from_bytes

    sig = signature_from_bytes(bytes(64))
    assert len(sig) == 64


def test_signature_from_bytes_wrong_length() -> None:
    from samp import signature_from_bytes

    with pytest.raises(SampError):
        signature_from_bytes(bytes(10))


def test_genesis_hash_from_bytes() -> None:
    from samp import genesis_hash_from_bytes

    gh = genesis_hash_from_bytes(bytes(32))
    assert len(gh) == 32


def test_genesis_hash_from_bytes_wrong_length() -> None:
    from samp import genesis_hash_from_bytes

    with pytest.raises(SampError):
        genesis_hash_from_bytes(bytes(10))
