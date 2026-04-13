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


# --- types.py: pubkey_zero ---


def test_pubkey_zero() -> None:
    from samp import pubkey_zero

    pk = pubkey_zero()
    assert len(pk) == 32
    assert pk == bytes(32)


# --- types.py: capsules_from_bytes non-multiple ---


def test_capsules_from_bytes_non_multiple() -> None:
    from samp import capsules_from_bytes

    with pytest.raises(SampError):
        capsules_from_bytes(bytes(34))


# --- types.py: capsules_count ---


def test_capsules_count() -> None:
    from samp import capsules_count, capsules_from_bytes

    c = capsules_from_bytes(bytes(33 * 3))
    assert capsules_count(c) == 3


# --- types.py: out-of-range validators ---


def test_block_number_out_of_range() -> None:
    from samp import block_number_from_int

    with pytest.raises(SampError):
        block_number_from_int(0xFFFF_FFFF + 1)
    with pytest.raises(SampError):
        block_number_from_int(-1)


def test_ext_index_out_of_range() -> None:
    from samp import ext_index_from_int

    with pytest.raises(SampError):
        ext_index_from_int(0x10000)


def test_extrinsic_nonce_out_of_range() -> None:
    from samp import extrinsic_nonce_from_int

    with pytest.raises(SampError):
        extrinsic_nonce_from_int(0xFFFF_FFFF + 1)


def test_spec_version_out_of_range() -> None:
    from samp import spec_version_from_int

    with pytest.raises(SampError):
        spec_version_from_int(0xFFFF_FFFF + 1)


def test_tx_version_out_of_range() -> None:
    from samp import tx_version_from_int

    with pytest.raises(SampError):
        tx_version_from_int(0xFFFF_FFFF + 1)


def test_pallet_idx_out_of_range() -> None:
    from samp import pallet_idx_from_int

    with pytest.raises(SampError):
        pallet_idx_from_int(256)


def test_call_idx_out_of_range() -> None:
    from samp import call_idx_from_int

    with pytest.raises(SampError):
        call_idx_from_int(256)


# --- types.py: BlockRef.is_zero ---


def test_block_ref_is_zero() -> None:
    from samp import BlockRef

    assert BlockRef.zero().is_zero() is True
    assert BlockRef.from_parts(1, 0).is_zero() is False


# --- types.py: ChannelName.byte_length ---


def test_channel_name_byte_length() -> None:
    name = ChannelName.parse("test")
    assert name.byte_length() == 4


# --- types.py: ChannelDescription.byte_length ---


def test_channel_desc_byte_length() -> None:
    desc = ChannelDescription.parse("hello")
    assert desc.byte_length() == 5


# --- types.py: Ss58Address.__str__ ---


def test_ss58_address_str() -> None:
    from samp import Ss58Address, pubkey_from_bytes, ss58_prefix_from_int

    pk = pubkey_from_bytes(bytes(32))
    addr = Ss58Address.encode(pk, ss58_prefix_from_int(42))
    assert str(addr) == addr.as_str()


# --- secret.py: __str__ methods ---


def test_seed_str_redacted() -> None:
    s = Seed.from_bytes(bytes(32))
    assert str(s) == "Seed([REDACTED])"


def test_view_scalar_str_redacted() -> None:
    from samp import ViewScalar

    vs = ViewScalar.from_bytes(bytes(32))
    assert str(vs) == "ViewScalar([REDACTED])"


def test_content_key_str_redacted() -> None:
    from samp import ContentKey

    ck = ContentKey.from_bytes(bytes(32))
    assert str(ck) == "ContentKey([REDACTED])"


# --- secret.py: ContentKey.expose_secret ---


def test_content_key_expose_secret() -> None:
    from samp import ContentKey

    raw = bytes(range(32))
    ck = ContentKey.from_bytes(raw)
    assert ck.expose_secret() == raw
