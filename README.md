<h1 align="center">SAMP - Substrate Account Messaging Protocol</h1>

<p align="center">
  <strong>Your wallet address is your identity.</strong>
</p>

<p align="center">
  <a href="https://codecov.io/gh/samp-org/samp"><img src="https://codecov.io/gh/samp-org/samp/graph/badge.svg" alt="codecov" /></a>
</p>

<p align="center">
  <a href="#how-it-works">How it works</a> •
  <a href="#message-types">Message types</a> •
  <a href="#sdks">SDKs</a> •
  <a href="#specification">Specification</a> •
  <a href="#mirrors">Mirrors</a>
</p>

---

Open protocol for signed, encrypted messaging between accounts on any Substrate blockchain. No servers, no registration.

Messages are `system.remark_with_event` extrinsics. The extrinsic signature authenticates the sender. The account's sr25519 public key doubles as the ECDH encryption key: encrypting to someone requires only their address.

```python
from samp import encode_public, encode_encrypted, encrypt, compute_view_tag, sr25519_signing_scalar
import os

# Public message
remark = encode_public(recipient_pubkey, "Hello from SAMP")

# Encrypted message
nonce = os.urandom(12)  # 12-byte encryption nonce (not the Substrate tx nonce)
ciphertext = encrypt(b"Private message", recipient_pubkey, nonce, sender_seed)
view_tag = compute_view_tag(sender_seed, recipient_pubkey, nonce)
remark = encode_encrypted(0x11, view_tag, nonce, ciphertext)

# Submit `remark` as a system.remark_with_event extrinsic on any Substrate chain.
```

<details>
<summary><b>Same thing in Rust, Go, and TypeScript</b></summary>

**Rust**

```rust
use samp::{encode_public, encode_encrypted, encrypt, compute_view_tag};

let remark = encode_public(&recipient, b"Hello from SAMP");

let nonce: [u8; 12] = rand::random(); // 12-byte encryption nonce (not the Substrate tx nonce)
let ciphertext = encrypt(b"Private message", &recipient_pubkey, &nonce, &seed)?;
let tag = compute_view_tag(&seed, &recipient_pubkey, &nonce)?;
let remark = encode_encrypted(0x11, tag, &nonce, &ciphertext);
```

**Go**

```go
import samp "github.com/samp-org/samp/go"

remark := samp.EncodePublic(recipient, []byte("Hello from SAMP"))

nonce := make([]byte, 12)
rand.Read(nonce) // 12-byte encryption nonce (not the Substrate tx nonce)
ciphertext, _ := samp.Encrypt([]byte("Private message"), recipientPub, nonce, seed)
tag := samp.ComputeViewTag(seed, recipientPub, nonce)
remark = samp.EncodeEncrypted(0x11, tag, nonce, ciphertext)
```

**TypeScript**

```typescript
import { encodePublic, encodeEncrypted, encrypt, computeViewTag } from "samp-core";

const remark = encodePublic(recipient, new TextEncoder().encode("Hello from SAMP"));

const nonce = crypto.getRandomValues(new Uint8Array(12)); // 12-byte encryption nonce (not the Substrate tx nonce)
const ciphertext = encrypt(new TextEncoder().encode("Private message"), recipientPub, nonce, seed);
const tag = computeViewTag(seed, recipientPub, nonce);
const encRemark = encodeEncrypted(0x11, tag, nonce, ciphertext);
```

</details>

<details>
<summary><b>Installation</b></summary>

**Rust**

```toml
[dependencies]
samp-core = "1.1"
```

**Python**

```
pip install samp-core
```

**Go**

```
go get github.com/samp-org/samp/go
```

**TypeScript**

```
npm install samp-core
```

</details>

## How it works

Every Substrate account already has three things: an address (routing), a public key (encryption), and a signing key (authentication). SAMP turns these into a messaging protocol without adding any new identity layer or infrastructure beyond the chain.

1. Alice writes a message and encodes it as a SAMP remark (public or encrypted)
2. Alice submits the remark as a `system.remark_with_event` extrinsic
3. Bob reads finalized blocks, finds SAMP remarks, decrypts those addressed to him
4. The extrinsic signature proves Alice sent it. The block timestamp proves when.

No relay servers. No message queues. The blockchain is the transport.

## Message types

| Byte | Type | Description |
|------|------|-------------|
| `0x10` | Public | Unencrypted message to a specific recipient |
| `0x11` | Encrypted | 1:1 encrypted with ECDH + ChaCha20-Poly1305 |
| `0x12` | Thread | Encrypted with DAG references for conversation threading |
| `0x13` | Channel creation | Creates a named public channel |
| `0x14` | Channel message | Post to a public channel with DAG references |
| `0x15` | Group message | Encrypted for N recipients, each decrypts independently |

Encryption uses Ristretto255 ECDH for key agreement, HKDF-SHA256 for key derivation, and ChaCha20-Poly1305 for authenticated encryption. A 1-byte view tag lets recipients reject non-matching messages without attempting decryption (255/256 rejection rate).

## Specification

[`specs/samp.md`](specs/samp.md) is the authority. It covers wire formats, encryption, DAG threading, processing rules, and security properties.

## SDKs

Four implementations. Same API surface. Same byte output. All test against shared [test vectors](e2e/test-vectors.json).

| Language | Path | Tests |
|----------|------|-------|
| Rust | [`rust/`](rust/) | `cargo test` (216 tests) |
| Python | [`python/`](python/) | `pytest tests/` (139 tests) |
| Go | [`go/`](go/) | `go test ./...` |
| TypeScript | [`typescript/`](typescript/) | `npm test` (120 tests) |

## Repository layout

```
specs/          Protocol specification (samp.md)
rust/           Rust SDK (reference implementation)
python/         Python SDK + native crypto extension (PyO3)
go/             Go SDK
typescript/     TypeScript SDK (@noble libraries)
e2e/            Shared test vectors and deterministic generator
```

## Mirrors

A SAMP mirror indexes remarks from a Substrate node and serves them via HTTP API. Clients use mirrors to discover messages without scanning the full chain. Mirrors never see decrypted content. Clients verify all data against the chain.

The [`samp-org/mirror-template`](https://github.com/samp-org/mirror-template) is a ready-to-deploy mirror for any Substrate chain. It indexes all SAMP remarks into SQLite and exposes a REST API for querying by content type, sender, or channel.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Spec changes go in separate PRs from code. New implementations must pass all shared test vectors.

## License

MIT. See [LICENSE](LICENSE).
