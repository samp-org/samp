import samp_crypto


def test_public_from_seed_returns_32_bytes() -> None:
    pub = samp_crypto.public_from_seed(b"\x01" * 32)
    assert isinstance(pub, bytes)
    assert len(pub) == 32


def test_encrypt_decrypt_roundtrip() -> None:
    sender_seed = b"\x01" * 32
    recipient_seed = b"\x02" * 32
    nonce = b"\x03" * 12
    plaintext = b"hello samp"

    recipient_pub = samp_crypto.public_from_seed(recipient_seed)
    recipient_scalar = samp_crypto.sr25519_signing_scalar(recipient_seed)

    content = samp_crypto.encrypt_content(plaintext, recipient_pub, nonce, sender_seed)
    assert len(content) == 80 + len(plaintext)

    decrypted = samp_crypto.decrypt_content(content, recipient_scalar, nonce)
    assert decrypted == plaintext

    decrypted_sender = samp_crypto.decrypt_as_sender(content, sender_seed, nonce)
    assert decrypted_sender == plaintext


def test_view_tag_agreement() -> None:
    sender_seed = b"\x07" * 32
    recipient_seed = b"\x09" * 32
    nonce = b"\x0b" * 12

    recipient_pub = samp_crypto.public_from_seed(recipient_seed)
    recipient_scalar = samp_crypto.sr25519_signing_scalar(recipient_seed)

    content = samp_crypto.encrypt_content(b"x", recipient_pub, nonce, sender_seed)
    sender_tag = samp_crypto.compute_view_tag(sender_seed, recipient_pub, nonce)
    recipient_tag = samp_crypto.check_view_tag(recipient_scalar, content)
    assert sender_tag == recipient_tag
