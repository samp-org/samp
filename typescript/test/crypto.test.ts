import { describe, it, expect } from "vitest";
import {
  Nonce,
  Plaintext,
  SampError,
  Seed,
  decrypt,
  decryptAsSender,
  decryptFromGroup,
  encrypt,
  encryptForGroup,
  publicFromSeed,
  sr25519SigningScalar,
  unsealRecipient,
} from "../src/index.js";

const SENDER_SEED = Seed.fromBytes(new Uint8Array(32).fill(0xaa));
const RECIPIENT_SEED = Seed.fromBytes(new Uint8Array(32).fill(0xbb));
const NONCE = Nonce.fromBytes(new Uint8Array(12).fill(0x01));

describe("decrypt wrong key", () => {
  it("fails with wrong scalar", () => {
    const recipientPub = publicFromSeed(RECIPIENT_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("hello world"));
    const ct = encrypt(pt, recipientPub, NONCE, SENDER_SEED);

    const wrongScalar = sr25519SigningScalar(SENDER_SEED);
    expect(() => decrypt(ct, NONCE, wrongScalar)).toThrow();
  });
});

describe("encrypt/decrypt as sender", () => {
  it("roundtrips plaintext", () => {
    const recipientPub = publicFromSeed(RECIPIENT_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("roundtrip test"));
    const ct = encrypt(pt, recipientPub, NONCE, SENDER_SEED);

    const recovered = decryptAsSender(ct, NONCE, SENDER_SEED);
    expect(new TextDecoder().decode(recovered)).toBe("roundtrip test");
  });
});

describe("unseal recipient", () => {
  it("recovers recipient pubkey", () => {
    const recipientPub = publicFromSeed(RECIPIENT_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("sealed"));
    const ct = encrypt(pt, recipientPub, NONCE, SENDER_SEED);

    const unsealed = unsealRecipient(ct, NONCE, SENDER_SEED);
    expect(Buffer.from(unsealed)).toEqual(Buffer.from(recipientPub));
  });
});

describe("group encrypt single member", () => {
  it("encrypts and decrypts for one member", () => {
    const recipientPub = publicFromSeed(RECIPIENT_SEED);
    const recipientScalar = sr25519SigningScalar(RECIPIENT_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("group msg"));

    const { ephPubkey, capsules, ciphertext } = encryptForGroup(
      pt,
      [recipientPub],
      NONCE,
      SENDER_SEED,
    );

    const content = new Uint8Array(ephPubkey.length + capsules.length + ciphertext.length);
    content.set(ephPubkey, 0);
    content.set(capsules, ephPubkey.length);
    content.set(ciphertext, ephPubkey.length + capsules.length);

    const recovered = decryptFromGroup(content, recipientScalar, NONCE, 1);
    expect(new TextDecoder().decode(recovered)).toBe("group msg");
  });
});
