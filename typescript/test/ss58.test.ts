import { describe, it, expect } from "vitest";
import { Ss58Address, Ss58Prefix, Pubkey } from "../src/index.js";

const testPubkey = Pubkey.fromBytes(
  new Uint8Array([
    0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd,
    0x04, 0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3,
    0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d,
  ]),
);

describe("ss58", () => {
  it("encode + decode round trip (prefix 42)", () => {
    const addr = Ss58Address.encode(testPubkey, Ss58Prefix.SUBSTRATE_GENERIC);
    const parsed = Ss58Address.parse(addr.asString());
    expect(parsed.asString()).toBe(addr.asString());
    expect(Buffer.from(parsed.pubkey())).toEqual(Buffer.from(testPubkey));
    expect(Ss58Prefix.get(parsed.prefix())).toBe(42);
  });

  it("encode + decode round trip (prefix 0)", () => {
    const addr = Ss58Address.encode(testPubkey, Ss58Prefix.POLKADOT);
    const parsed = Ss58Address.parse(addr.asString());
    expect(parsed.asString()).toBe(addr.asString());
    expect(Buffer.from(parsed.pubkey())).toEqual(Buffer.from(testPubkey));
    expect(Ss58Prefix.get(parsed.prefix())).toBe(0);
  });

  it("decode with bad checksum throws", () => {
    const addr = Ss58Address.encode(testPubkey, Ss58Prefix.SUBSTRATE_GENERIC);
    const s = addr.asString();
    const lastChar = s[s.length - 1]!;
    const replacement = lastChar === "A" ? "B" : "A";
    const corrupted = s.slice(0, -1) + replacement;
    expect(() => Ss58Address.parse(corrupted)).toThrow("ss58 bad checksum");
  });

  it("decode too short throws", () => {
    expect(() => Ss58Address.parse("abc")).toThrow("ss58 too short");
  });

  it("decode empty string throws", () => {
    expect(() => Ss58Address.parse("")).toThrow("ss58 too short");
  });

  it("prefix boundary: 63 valid, 64 rejected", () => {
    const prefix63 = Ss58Prefix.from(63);
    const addr63 = Ss58Address.encode(testPubkey, prefix63);
    const parsed = Ss58Address.parse(addr63.asString());
    expect(Ss58Prefix.get(parsed.prefix())).toBe(63);

    expect(() => Ss58Prefix.from(64)).toThrow();
  });

  it("parse rejects address with prefix byte >= 64", () => {
    // Manually construct a base58-encoded address with prefix byte 64
    // by encoding raw bytes [64, ...pubkey, checksum]
    // The parse function should reject prefix byte >= 64
    const { blake2b } = require("@noble/hashes/blake2b");
    const payload = new Uint8Array(33);
    payload[0] = 64;
    payload.set(testPubkey, 1);
    const SS58PRE = new TextEncoder().encode("SS58PRE");
    const h = blake2b.create({ dkLen: 64 });
    h.update(SS58PRE);
    h.update(payload);
    const sum = h.digest();
    const full = new Uint8Array(35);
    full.set(payload, 0);
    full[33] = sum[0];
    full[34] = sum[1];
    // bs58 encode
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const digits: number[] = [0];
    for (const b of full) {
      let carry = b;
      for (let i = 0; i < digits.length; i++) {
        carry += (digits[i] ?? 0) * 256;
        digits[i] = carry % 58;
        carry = Math.floor(carry / 58);
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = Math.floor(carry / 58);
      }
    }
    let encoded = "";
    for (const b of full) {
      if (b === 0) encoded += ALPHABET[0];
      else break;
    }
    for (let i = digits.length - 1; i >= 0; i--) {
      encoded += ALPHABET[digits[i] ?? 0];
    }
    expect(() => Ss58Address.parse(encoded)).toThrow("ss58 prefix unsupported");
  });

  it("decode invalid base58 character throws", () => {
    expect(() => Ss58Address.parse("0OIl")).toThrow("ss58");
  });
});
