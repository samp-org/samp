# @samp-org/samp

TypeScript implementation of [SAMP](https://github.com/samp-org/samp) (Substrate Account Messaging Protocol).

## Install

```
npm install github:samp-org/samp
```

## Usage

```typescript
import {
  encodePublic, encodeEncrypted, encrypt, decrypt,
  computeViewTag, sr25519SigningScalar, decodeRemark,
  CONTENT_TYPE_ENCRYPTED,
} from "@samp-org/samp";

const senderSeed = new Uint8Array(32);  // your sr25519 seed
const recipientPub = new Uint8Array(32); // recipient's sr25519 public key

// Public message
const remark = encodePublic(recipientPub, new TextEncoder().encode("Hello from TypeScript"));

// Encrypted message
const nonce = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = encrypt(new TextEncoder().encode("Private message"), recipientPub, nonce, senderSeed);
const tag = computeViewTag(senderSeed, recipientPub, nonce);
const encRemark = encodeEncrypted(CONTENT_TYPE_ENCRYPTED, tag, nonce, ciphertext);

// Decrypt
const scalar = sr25519SigningScalar(recipientSeed);
const parsed = decodeRemark(encRemark);
const plaintext = decrypt(parsed.content, scalar, parsed.nonce);
```

## API

### Wire

| Function | Description |
|----------|-------------|
| `encodePublic` | Public message (`0x10`) |
| `encodeEncrypted` | Encrypted or thread message (`0x11`/`0x12`) |
| `encodeChannelCreate` | Channel creation (`0x13`) |
| `encodeChannelMsg` | Channel message (`0x14`) |
| `encodeGroup` | Group message (`0x15`) |
| `decodeRemark` | Parse any SAMP remark → `Remark` |
| `encodeThreadContent` / `decodeThreadContent` | Thread plaintext (refs + body) |
| `encodeChannelContent` / `decodeChannelContent` | Channel plaintext (refs + body) |
| `decodeGroupContent` | Group plaintext (refs + body) |
| `encodeGroupMembers` / `decodeGroupMembers` | Group member list |
| `channelRefFromRecipient` | Extract channel BlockRef from recipient field |

### Crypto

| Function | Description |
|----------|-------------|
| `encrypt` / `decrypt` | 1:1 ECDH + ChaCha20-Poly1305 |
| `decryptAsSender` | Sender self-decryption via sealed_to |
| `encryptForGroup` / `decryptFromGroup` | Multi-recipient encryption |
| `sr25519SigningScalar` | Derive signing scalar from sr25519 seed |
| `publicFromSeed` | Derive public key from seed |
| `computeViewTag` / `checkViewTag` | 1-byte recipient filter |
| `unsealRecipient` | Recover recipient from sealed_to field |
| `buildCapsules` / `scanCapsules` | Group capsule construction and scanning |

### Types

`BlockRef`, `Remark`, `SampError`

### Constants

`SAMP_VERSION`, `CONTENT_TYPE_PUBLIC`, `CONTENT_TYPE_ENCRYPTED`, `CONTENT_TYPE_THREAD`, `CONTENT_TYPE_CHANNEL_CREATE`, `CONTENT_TYPE_CHANNEL`, `CONTENT_TYPE_GROUP`, `CAPSULE_SIZE`, `ENCRYPTED_OVERHEAD`, `CHANNEL_NAME_MAX`, `CHANNEL_DESC_MAX`

## Test

```
npm test
```
