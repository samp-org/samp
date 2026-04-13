import { describe, it, expect } from "vitest";
import {
  BlockNumber,
  BlockRef,
  CallIdx,
  Capsules,
  CAPSULE_SIZE,
  ChannelDescription,
  ChannelName,
  Ciphertext,
  ContentKey,
  EphPubkey,
  ExtIndex,
  ExtrinsicNonce,
  GenesisHash,
  Nonce,
  PalletIdx,
  SampError,
  Seed,
  Signature,
  SpecVersion,
  Ss58Prefix,
  TxVersion,
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

describe("BlockNumber", () => {
  it("valid u32 works", () => {
    expect(BlockNumber.get(BlockNumber.from(0))).toBe(0);
    expect(BlockNumber.get(BlockNumber.from(0xffff_ffff))).toBe(0xffff_ffff);
  });

  it("negative throws", () => {
    expect(() => BlockNumber.from(-1)).toThrow(SampError);
  });

  it("above u32 throws", () => {
    expect(() => BlockNumber.from(0x1_0000_0000)).toThrow(SampError);
  });

  it("non-integer throws", () => {
    expect(() => BlockNumber.from(1.5)).toThrow(SampError);
  });
});

describe("ExtIndex", () => {
  it("valid u16 works", () => {
    expect(ExtIndex.get(ExtIndex.from(0))).toBe(0);
    expect(ExtIndex.get(ExtIndex.from(0xffff))).toBe(0xffff);
  });

  it("negative throws", () => {
    expect(() => ExtIndex.from(-1)).toThrow(SampError);
  });

  it("above u16 throws", () => {
    expect(() => ExtIndex.from(0x10000)).toThrow(SampError);
  });

  it("non-integer throws", () => {
    expect(() => ExtIndex.from(0.5)).toThrow(SampError);
  });
});

describe("ExtrinsicNonce", () => {
  it("valid u32 works", () => {
    expect(ExtrinsicNonce.get(ExtrinsicNonce.from(42))).toBe(42);
  });

  it("negative throws", () => {
    expect(() => ExtrinsicNonce.from(-1)).toThrow(SampError);
  });

  it("above u32 throws", () => {
    expect(() => ExtrinsicNonce.from(0x1_0000_0000)).toThrow(SampError);
  });

  it("non-integer throws", () => {
    expect(() => ExtrinsicNonce.from(2.7)).toThrow(SampError);
  });
});

describe("SpecVersion", () => {
  it("valid works", () => {
    expect(SpecVersion.get(SpecVersion.from(100))).toBe(100);
  });

  it("negative throws", () => {
    expect(() => SpecVersion.from(-1)).toThrow(SampError);
  });

  it("above u32 throws", () => {
    expect(() => SpecVersion.from(0x1_0000_0000)).toThrow(SampError);
  });
});

describe("TxVersion", () => {
  it("valid works", () => {
    expect(TxVersion.get(TxVersion.from(1))).toBe(1);
  });

  it("negative throws", () => {
    expect(() => TxVersion.from(-1)).toThrow(SampError);
  });

  it("above u32 throws", () => {
    expect(() => TxVersion.from(0x1_0000_0000)).toThrow(SampError);
  });
});

describe("PalletIdx", () => {
  it("valid u8 works", () => {
    expect(PalletIdx.get(PalletIdx.from(0))).toBe(0);
    expect(PalletIdx.get(PalletIdx.from(0xff))).toBe(0xff);
  });

  it("negative throws", () => {
    expect(() => PalletIdx.from(-1)).toThrow(SampError);
  });

  it("above u8 throws", () => {
    expect(() => PalletIdx.from(256)).toThrow(SampError);
  });
});

describe("CallIdx", () => {
  it("valid u8 works", () => {
    expect(CallIdx.get(CallIdx.from(7))).toBe(7);
  });

  it("negative throws", () => {
    expect(() => CallIdx.from(-1)).toThrow(SampError);
  });

  it("above u8 throws", () => {
    expect(() => CallIdx.from(256)).toThrow(SampError);
  });
});

describe("Ss58Prefix", () => {
  it("valid range works", () => {
    expect(Ss58Prefix.get(Ss58Prefix.from(0))).toBe(0);
    expect(Ss58Prefix.get(Ss58Prefix.from(63))).toBe(63);
  });

  it(">= 64 throws", () => {
    expect(() => Ss58Prefix.from(64)).toThrow(SampError);
  });

  it("negative throws", () => {
    expect(() => Ss58Prefix.from(-1)).toThrow(SampError);
  });
});

describe("Capsules", () => {
  it("valid multiple of CAPSULE_SIZE works", () => {
    const c = Capsules.fromBytes(new Uint8Array(CAPSULE_SIZE * 2));
    expect(Capsules.count(c)).toBe(2);
  });

  it("non-multiple of CAPSULE_SIZE throws", () => {
    expect(() => Capsules.fromBytes(new Uint8Array(CAPSULE_SIZE + 1))).toThrow(SampError);
  });

  it("empty is valid (0 capsules)", () => {
    const c = Capsules.fromBytes(new Uint8Array(0));
    expect(Capsules.count(c)).toBe(0);
  });
});

describe("ChannelName boundary", () => {
  it("exactly 32 bytes accepted", () => {
    const name = ChannelName.parse("a".repeat(32));
    expect(name.byteLength()).toBe(32);
  });

  it("empty throws", () => {
    expect(() => ChannelName.parse("")).toThrow(SampError);
  });
});

describe("ChannelDescription boundary", () => {
  it("exactly 128 bytes accepted", () => {
    const desc = ChannelDescription.parse("a".repeat(128));
    expect(desc.byteLength()).toBe(128);
  });
});

describe("BlockRef", () => {
  it("zero is zero", () => {
    expect(BlockRef.zero().isZero()).toBe(true);
  });

  it("non-zero is not zero", () => {
    expect(BlockRef.fromParts(1, 0).isZero()).toBe(false);
  });
});
