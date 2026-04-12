import { describe, it, expect } from "vitest";
import {
  ChannelDescription,
  ChannelName,
  ContentType,
  Nonce,
  Plaintext,
  Pubkey,
  RemarkBytes,
  SampError,
  Seed,
  ViewTag,
  decodeGroupMembers,
  decodeRemark,
  decodeThreadContent,
  encodeChannelCreate,
  encodeEncrypted,
  encodeGroupMembers,
  encrypt,
  isSampRemark,
  publicFromSeed,
} from "../src/index.js";

describe("decodeRemark", () => {
  it("rejects empty bytes", () => {
    expect(() => decodeRemark(RemarkBytes.fromBytes(new Uint8Array(0)))).toThrow(SampError);
  });
});

describe("isSampRemark", () => {
  it("returns false for non-SAMP prefix", () => {
    expect(isSampRemark(new Uint8Array([0x20, 0x00]))).toBe(false);
  });
});

describe("channel create round trip", () => {
  it("encodes and decodes name/description", () => {
    const name = ChannelName.parse("general");
    const desc = ChannelDescription.parse("A test channel");
    const encoded = encodeChannelCreate(name, desc);
    const decoded = decodeRemark(encoded);
    expect(decoded.type).toBe(ContentType.ChannelCreate);
    if (decoded.type === ContentType.ChannelCreate) {
      expect(decoded.name.asString()).toBe("general");
      expect(decoded.description.asString()).toBe("A test channel");
    }
  });
});

describe("decodeThreadContent", () => {
  it("rejects truncated data", () => {
    expect(() => decodeThreadContent(new Uint8Array(5))).toThrow(SampError);
  });
});

describe("encodeEncrypted round trip", () => {
  it("encodes and decodes through decodeRemark", () => {
    const senderSeed = Seed.fromBytes(new Uint8Array(32).fill(0xaa));
    const recipientPub = publicFromSeed(Seed.fromBytes(new Uint8Array(32).fill(0xbb)));
    const nonce = Nonce.fromBytes(new Uint8Array(12).fill(0x01));
    const pt = Plaintext.fromBytes(new TextEncoder().encode("round trip test"));
    const ct = encrypt(pt, recipientPub, nonce, senderSeed);

    const encoded = encodeEncrypted(ContentType.Encrypted, ViewTag.from(0), nonce, ct);
    const decoded = decodeRemark(encoded);
    expect(decoded.type).toBe(ContentType.Encrypted);
    if (decoded.type === ContentType.Encrypted) {
      expect(Buffer.from(decoded.nonce)).toEqual(Buffer.from(nonce));
      expect(Buffer.from(decoded.ciphertext)).toEqual(Buffer.from(ct));
    }
  });
});

describe("encodeGroupMembers + decodeGroupMembers round trip", () => {
  it("round-trips 2 pubkeys", () => {
    const pk1 = Pubkey.fromBytes(new Uint8Array(32).fill(0x01));
    const pk2 = Pubkey.fromBytes(new Uint8Array(32).fill(0x02));
    const encoded = encodeGroupMembers([pk1, pk2]);
    const { members, body } = decodeGroupMembers(encoded);
    expect(members.length).toBe(2);
    expect(Buffer.from(members[0]!)).toEqual(Buffer.from(pk1));
    expect(Buffer.from(members[1]!)).toEqual(Buffer.from(pk2));
    expect(body.length).toBe(0);
  });
});
