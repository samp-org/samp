import { describe, it, expect } from "vitest";
import {
  ChannelDescription,
  ChannelName,
  Ciphertext,
  ContentKey,
  EphPubkey,
  GenesisHash,
  Nonce,
  SampError,
  Seed,
  Signature,
  ViewScalar,
  ViewTag,
} from "../src/index.js";

describe("Seed", () => {
  it("toString is redacted", () => {
    const seed = Seed.fromBytes(new Uint8Array(32));
    expect(seed.toString()).toContain("REDACTED");
  });

  it("wrong length throws SampError", () => {
    expect(() => Seed.fromBytes(new Uint8Array(5))).toThrow(SampError);
  });
});

describe("ChannelName", () => {
  it("rejects too-long name", () => {
    expect(() => ChannelName.parse("x".repeat(33))).toThrow(SampError);
  });

  it("accepts valid name", () => {
    const name = ChannelName.parse("test");
    expect(name.asString()).toBe("test");
  });
});

describe("ChannelDescription", () => {
  it("rejects too-long description", () => {
    expect(() => ChannelDescription.parse("x".repeat(129))).toThrow(SampError);
  });
});

describe("ViewScalar", () => {
  it("toString is redacted", () => {
    const vs = ViewScalar.fromBytes(new Uint8Array(32));
    expect(vs.toString()).toContain("REDACTED");
  });

  it("wrong length throws", () => {
    expect(() => ViewScalar.fromBytes(new Uint8Array(5))).toThrow(SampError);
  });
});

describe("ContentKey", () => {
  it("toString is redacted", () => {
    const ck = ContentKey.fromBytes(new Uint8Array(32));
    expect(ck.toString()).toContain("REDACTED");
  });

  it("wrong length throws", () => {
    expect(() => ContentKey.fromBytes(new Uint8Array(5))).toThrow(SampError);
  });
});

describe("ViewTag", () => {
  it("ViewTag.from(42) works", () => {
    const vt = ViewTag.from(42);
    expect(ViewTag.get(vt)).toBe(42);
  });

  it("out of range throws", () => {
    expect(() => ViewTag.from(256)).toThrow(SampError);
  });
});

describe("EphPubkey", () => {
  it("fromBytes with 32 bytes works", () => {
    const ep = EphPubkey.fromBytes(new Uint8Array(32));
    expect(ep.length).toBe(32);
  });

  it("wrong length throws", () => {
    expect(() => EphPubkey.fromBytes(new Uint8Array(10))).toThrow(SampError);
  });
});

describe("Ciphertext", () => {
  it("fromBytes with 80 bytes works", () => {
    const ct = Ciphertext.fromBytes(new Uint8Array(80));
    expect(ct.length).toBe(80);
  });
});

describe("GenesisHash", () => {
  it("fromBytes with 32 bytes works", () => {
    const gh = GenesisHash.fromBytes(new Uint8Array(32));
    expect(gh.length).toBe(32);
  });

  it("wrong length throws", () => {
    expect(() => GenesisHash.fromBytes(new Uint8Array(10))).toThrow(SampError);
  });
});

describe("Signature", () => {
  it("fromBytes with 64 bytes works", () => {
    const sig = Signature.fromBytes(new Uint8Array(64));
    expect(sig.length).toBe(64);
  });

  it("wrong length throws", () => {
    expect(() => Signature.fromBytes(new Uint8Array(10))).toThrow(SampError);
  });
});

describe("Nonce", () => {
  it("fromBytes with 12 bytes works", () => {
    const n = Nonce.fromBytes(new Uint8Array(12));
    expect(n.length).toBe(12);
  });

  it("wrong length throws", () => {
    expect(() => Nonce.fromBytes(new Uint8Array(5))).toThrow(SampError);
  });
});
