# @samp-org/samp

TypeScript implementation of [SAMP](https://github.com/samp-org/samp) (Substrate Account Messaging Protocol).

## Install

```
npm install github:samp-org/samp
```

## Usage

```typescript
import {
  ContentType, Nonce, Plaintext, Pubkey, Seed,
  computeViewTag, decodeRemark, decrypt, encodeEncrypted, encodePublic,
  encrypt, sr25519SigningScalar,
} from "@samp-org/samp";

const senderSeed = Seed.fromBytes(new Uint8Array(32));   // your sr25519 seed
const recipientPub = Pubkey.fromBytes(new Uint8Array(32)); // recipient's sr25519 public key

// Public message
const remark = encodePublic(recipientPub, "Hello from TypeScript");

// Encrypted message
const nonce = Nonce.fromBytes(crypto.getRandomValues(new Uint8Array(12)));
const plaintext = Plaintext.fromBytes(new TextEncoder().encode("Private message"));
const ciphertext = encrypt(plaintext, recipientPub, nonce, senderSeed);
const tag = computeViewTag(senderSeed, recipientPub, nonce);
const encRemark = encodeEncrypted(ContentType.Encrypted, tag, nonce, ciphertext);

// Decrypt
const recipientSeed = Seed.fromBytes(new Uint8Array(32));
const scalar = sr25519SigningScalar(recipientSeed);
const parsed = decodeRemark(encRemark);
if (parsed.type !== ContentType.Encrypted) throw new Error("expected Encrypted");
const clear = decrypt(parsed.ciphertext, parsed.nonce, scalar);
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

`SAMP_VERSION`, `ContentType` (enum), `CAPSULE_SIZE`, `CHANNEL_NAME_MAX`, `CHANNEL_DESC_MAX`

## Test

```
npm test
```
