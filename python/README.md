# samp

Python implementation of [SAMP](https://github.com/samp-org/samp) (Substrate Account Messaging Protocol). Crypto operations use a native Rust extension via PyO3.

## Install

Requires a Rust toolchain for the native crypto extension.

```
pip install maturin
cd python/samp-crypto && maturin develop && cd ../..
cd python && pip install -e .
```

## Usage

```python
import os

from samp import (
    EncryptedRemark, Seed, decode_remark,
    nonce_from_bytes, plaintext_from_bytes, pubkey_from_bytes, sr25519_signing_scalar,
)
from samp.encryption import compute_view_tag, decrypt, encrypt
from samp.wire import ContentType, encode_encrypted, encode_public

sender_seed = Seed.from_bytes(bytes.fromhex("e5be9a5092b81bca" + "00" * 24))
recipient_pub = pubkey_from_bytes(bytes.fromhex("8eaf04151687736" + "0" + "00" * 24))

# Public message
remark = encode_public(recipient_pub, "Hello from Python")

# Encrypted message
nonce = nonce_from_bytes(os.urandom(12))
plaintext = plaintext_from_bytes(b"Private message")
ciphertext = encrypt(plaintext, recipient_pub, nonce, sender_seed)
tag = compute_view_tag(sender_seed, recipient_pub, nonce)
enc_remark = encode_encrypted(ContentType.ENCRYPTED, tag, nonce, ciphertext)

# Decrypt
recipient_seed = Seed.from_bytes(bytes(32))
scalar = sr25519_signing_scalar(recipient_seed)
parsed = decode_remark(enc_remark)
assert isinstance(parsed, EncryptedRemark)
clear = decrypt(parsed.ciphertext, parsed.nonce, scalar)
```

## API

### Wire

| Function | Description |
|----------|-------------|
| `encode_public` | Public message (`0x10`) |
| `encode_encrypted` | Encrypted or thread message (`0x11`/`0x12`) |
| `encode_channel_create` | Channel creation (`0x13`) |
| `encode_channel_msg` | Channel message (`0x14`) |
| `encode_group` | Group message (`0x15`) |
| `decode_remark` | Parse any SAMP remark → `Remark` dataclass |
| `encode_thread_content` / `decode_thread_content` | Thread plaintext (refs + body) |
| `encode_channel_content` / `decode_channel_content` | Channel plaintext (refs + body) |
| `decode_group_content` | Group plaintext (refs + body) |
| `encode_group_members` / `decode_group_members` | Group member list |
| `channel_ref_from_recipient` | Extract channel ref from recipient field |

### Crypto

| Function | Description |
|----------|-------------|
| `encrypt` / `decrypt` | 1:1 ECDH + ChaCha20-Poly1305 |
| `decrypt_as_sender` | Sender self-decryption via sealed_to |
| `encrypt_for_group` / `decrypt_from_group` | Multi-recipient encryption |
| `sr25519_signing_scalar` | Derive signing scalar from sr25519 seed |
| `public_from_seed` | Derive public key from seed |
| `compute_view_tag` / `check_view_tag` | 1-byte recipient filter |
| `unseal_recipient` | Recover recipient from sealed_to field |
| `build_capsules` / `scan_capsules` | Group capsule construction and scanning |

### Types

`Remark` (dataclass), `SampError` (exception)

## Test

```
pytest tests/ -v
```
