import { describe, it, expect, vi } from "vitest";
import {
  CAPSULE_SIZE,
  Nonce,
  Plaintext,
  SampError,
  Seed,
  decrypt,
  decryptAsSender,
  decryptFromGroup,
  deriveGroupEphemeral,
  encrypt,
  encryptForGroupRandom,
  encryptForGroup,
  encryptRandom,
  publicFromSeed,
  randomNonce,
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

describe("random nonce helpers", () => {
  it("reads twelve bytes from Web Crypto", () => {
    vi.stubGlobal("crypto", {
      getRandomValues(values: Uint8Array): Uint8Array {
        expect(values.length).toBe(12);
        for (let i = 0; i < values.length; i++) {
          values[i] = i;
        }
        return values;
      },
    });
    try {
      expect(randomNonce()).toEqual(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]));
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("throws when Web Crypto is unavailable", () => {
    vi.stubGlobal("crypto", undefined);
    try {
      expect(() => randomNonce()).toThrow("secure random source unavailable");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("encryptRandom returns the nonce needed to decrypt", () => {
    const recipientPub = publicFromSeed(RECIPIENT_SEED);
    const recipientScalar = sr25519SigningScalar(RECIPIENT_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("secret"));
    const { nonce, ciphertext } = encryptRandom(pt, recipientPub, SENDER_SEED);
    const recovered = decrypt(ciphertext, nonce, recipientScalar);
    expect(new TextDecoder().decode(recovered)).toBe("secret");
  });

  it("encryptForGroupRandom returns the nonce needed to decrypt", () => {
    const recipientPub = publicFromSeed(RECIPIENT_SEED);
    const recipientScalar = sr25519SigningScalar(RECIPIENT_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("group secret"));
    const { nonce, ephPubkey, capsules, ciphertext } = encryptForGroupRandom(
      pt,
      [recipientPub],
      SENDER_SEED,
    );
    const content = new Uint8Array(ephPubkey.length + capsules.length + ciphertext.length);
    content.set(ephPubkey, 0);
    content.set(capsules, ephPubkey.length);
    content.set(ciphertext, ephPubkey.length + capsules.length);
    const recovered = decryptFromGroup(content, recipientScalar, nonce, 1);
    expect(new TextDecoder().decode(recovered)).toBe("group secret");
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

describe("decryptFromGroup view tag collision", () => {
  it("continues until a matching capsule authenticates", () => {
    const senderPub = publicFromSeed(SENDER_SEED);
    const recipientPub = publicFromSeed(RECIPIENT_SEED);
    const recipientScalar = sr25519SigningScalar(RECIPIENT_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("view tag collision"));

    const { ephPubkey, capsules, ciphertext } = encryptForGroup(
      pt,
      [senderPub, recipientPub],
      NONCE,
      SENDER_SEED,
    );

    const content = new Uint8Array(ephPubkey.length + capsules.length + ciphertext.length);
    content.set(ephPubkey, 0);
    content.set(capsules, ephPubkey.length);
    content.set(ciphertext, ephPubkey.length + capsules.length);
    content[32] = content[32 + CAPSULE_SIZE]!;

    expect(new TextDecoder().decode(decryptFromGroup(content, recipientScalar, NONCE, 2))).toBe(
      "view tag collision",
    );
    expect(new TextDecoder().decode(decryptFromGroup(content, recipientScalar, NONCE))).toBe(
      "view tag collision",
    );
  });
});

describe("deriveGroupEphemeral", () => {
  it("returns 32-byte scalar", () => {
    const result = deriveGroupEphemeral(SENDER_SEED, NONCE);
    expect(result.length).toBe(32);
  });

  it("deterministic for same inputs", () => {
    const a = deriveGroupEphemeral(SENDER_SEED, NONCE);
    const b = deriveGroupEphemeral(SENDER_SEED, NONCE);
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
  });
});

describe("decryptFromGroup wrong knownN", () => {
  it("throws with wrong knownN (too large)", () => {
    const recipientPub = publicFromSeed(RECIPIENT_SEED);
    const recipientScalar = sr25519SigningScalar(RECIPIENT_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("test"));

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

    expect(() => decryptFromGroup(content, recipientScalar, NONCE, 999)).toThrow(SampError);
  });
});

describe("decryptFromGroup loop exhaustion", () => {
  it("throws when no valid capsule found (non-member)", () => {
    const senderPub = publicFromSeed(SENDER_SEED);
    const pt = Plaintext.fromBytes(new TextEncoder().encode("secret"));

    const { ephPubkey, capsules, ciphertext } = encryptForGroup(
      pt,
      [senderPub],
      NONCE,
      SENDER_SEED,
    );

    const content = new Uint8Array(ephPubkey.length + capsules.length + ciphertext.length);
    content.set(ephPubkey, 0);
    content.set(capsules, ephPubkey.length);
    content.set(ciphertext, ephPubkey.length + capsules.length);

    const thirdPartyScalar = sr25519SigningScalar(Seed.fromBytes(new Uint8Array(32).fill(0xdd)));
    expect(() => decryptFromGroup(content, thirdPartyScalar, NONCE)).toThrow(SampError);
  });
});

describe("decryptFromGroup insufficient data", () => {
  it("throws on content < 32 bytes", () => {
    const scalar = sr25519SigningScalar(SENDER_SEED);
    expect(() => decryptFromGroup(new Uint8Array(10), scalar, NONCE)).toThrow(SampError);
  });
});
