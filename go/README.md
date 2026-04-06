# samp

Go implementation of [SAMP](https://github.com/samp-org/samp) (Substrate Account Messaging Protocol).

## Install

```
go get github.com/samp-org/samp/go
```

## Usage

```go
package main

import (
	"crypto/rand"
	samp "github.com/samp-org/samp/go"
)

func main() {
	var senderSeed [32]byte  // your sr25519 seed
	var recipientPub [32]byte // recipient's sr25519 public key

	// Public message
	remark := samp.EncodePublic(recipientPub[:], []byte("Hello from Go"))

	// Encrypted message
	nonce := make([]byte, 12)
	rand.Read(nonce)
	ciphertext, _ := samp.Encrypt([]byte("Private message"), recipientPub[:], nonce, senderSeed[:])
	tag, _ := samp.ComputeViewTag(senderSeed[:], recipientPub[:], nonce)
	remark = samp.EncodeEncrypted(samp.ContentTypeEncrypted, tag, nonce, ciphertext)

	// Decrypt
	scalar := samp.Sr25519SigningScalar(recipientSeed[:])
	parsed, _ := samp.DecodeRemark(remark)
	plaintext, _ := samp.Decrypt(parsed.Content, scalar.Bytes(), parsed.Nonce[:])
}
```

## API

### Wire

| Function | Description |
|----------|-------------|
| `EncodePublic` | Public message (`0x10`) |
| `EncodeEncrypted` | Encrypted or thread message (`0x11`/`0x12`) |
| `EncodeChannelCreate` | Channel creation (`0x13`) |
| `EncodeChannelMsg` | Channel message (`0x14`) |
| `EncodeGroup` | Group message (`0x15`) |
| `DecodeRemark` | Parse any SAMP remark → `*Remark` |
| `EncodeThreadContent` / `DecodeThreadContent` | Thread plaintext (refs + body) |
| `EncodeChannelContent` / `DecodeChannelContent` | Channel plaintext (refs + body) |
| `DecodeGroupContent` | Group plaintext (refs + body) |
| `EncodeGroupMembers` / `DecodeGroupMembers` | Group member list |
| `ChannelRefFromRecipient` | Extract channel BlockRef from recipient field |

### Crypto

| Function | Description |
|----------|-------------|
| `Encrypt` / `Decrypt` | 1:1 ECDH + ChaCha20-Poly1305 |
| `DecryptAsSender` | Sender self-decryption via sealed_to |
| `EncryptForGroup` / `DecryptFromGroup` | Multi-recipient encryption |
| `Sr25519SigningScalar` | Derive Ristretto255 scalar from sr25519 seed |
| `PublicFromSeed` | Derive public key from seed |
| `ComputeViewTag` / `CheckViewTag` | 1-byte recipient filter |
| `UnsealRecipient` | Recover recipient from sealed_to field |
| `BuildCapsules` / `ScanCapsules` | Group capsule construction and scanning |

### Types

`BlockRef`, `Remark`

## Test

```
go test ./...
```
