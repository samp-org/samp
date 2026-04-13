# samp

Rust implementation of [SAMP](https://github.com/samp-org/samp) (Substrate Account Messaging Protocol).

## Install

```toml
[dependencies]
samp = { git = "https://github.com/samp-org/samp", subdirectory = "rust" }
```

## Usage

```rust
use samp::encryption::{compute_view_tag, decrypt, encrypt, sr25519_signing_scalar};
use samp::secret::Seed;
use samp::types::{ContentType, Nonce, Plaintext, Pubkey};
use samp::wire::{decode_remark, encode_encrypted, encode_public, Remark};

let sender_seed = Seed::from_bytes([0u8; 32]); // your sr25519 seed
let recipient_pub = Pubkey::from_bytes([0u8; 32]); // recipient's sr25519 public key

// Public message
let remark = encode_public(&recipient_pub, "Hello from Rust");

// Encrypted message
let nonce = Nonce::from_bytes([0u8; 12]); // use a random 12-byte IV
let plaintext = Plaintext::from_bytes(b"Private message".to_vec());
let ciphertext = encrypt(&plaintext, &recipient_pub, &nonce, &sender_seed).unwrap();
let tag = compute_view_tag(&sender_seed, &recipient_pub, &nonce).unwrap();
let enc_remark = encode_encrypted(ContentType::Encrypted, tag, &nonce, &ciphertext);

// Decrypt
let recipient_seed = Seed::from_bytes([0u8; 32]);
let scalar = sr25519_signing_scalar(&recipient_seed);
let Remark::Encrypted { nonce: n, ciphertext: ct, .. } = decode_remark(&enc_remark).unwrap() else {
    panic!("expected Encrypted");
};
let plaintext = decrypt(&ct, &n, &scalar).unwrap();
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
| `decode_remark` | Parse any SAMP remark |
| `encode_thread_content` / `decode_thread_content` | Thread plaintext (refs + body) |
| `encode_channel_content` / `decode_channel_content` | Channel plaintext (refs + body) |
| `decode_group_content` | Group plaintext (refs + body) |
| `encode_group_members` / `decode_group_members` | Group member list |
| `channel_ref_from_recipient` | Extract channel BlockRef from recipient field |

### Crypto

| Function | Description |
|----------|-------------|
| `encrypt` / `decrypt` | 1:1 ECDH + ChaCha20-Poly1305 |
| `decrypt_as_sender` | Sender self-decryption via sealed_to |
| `encrypt_for_group` / `decrypt_from_group` | Multi-recipient encryption |
| `sr25519_signing_scalar` | Derive Ristretto255 scalar from sr25519 seed |
| `public_from_seed` | Derive public key from seed |
| `compute_view_tag` / `check_view_tag` | 1-byte recipient filter |
| `unseal_recipient` | Recover recipient from sealed_to field |
| `build_capsules` / `scan_capsules` | Group capsule construction and scanning |

### Types

`BlockRef`, `Remark`, `ContentType`, `SampError`, `GroupEncrypted`

## Test

```
cargo test
```

46 tests: 18 round-trip, 20 conformance (against shared `e2e/test-vectors.json`), 8 property-based (proptest).
