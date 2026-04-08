import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { decodeBytes, decodeCompact, encodeCompact } from "../src/scale.js";

const fixture = JSON.parse(
  readFileSync(resolve(__dirname, "../../e2e/scale-vectors.json"), "utf-8"),
);

function unhex(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s.replace(/^0x/, ""), "hex"));
}

describe("scale compact codec", () => {
  it("encodes and decodes mode 0 lower bound", () => {
    expect(encodeCompact(0n)).toEqual(new Uint8Array([0x00]));
    expect(decodeCompact(new Uint8Array([0x00]))).toEqual([0n, 1]);
  });

  it("encodes and decodes mode 0 upper bound", () => {
    expect(encodeCompact(63n)).toEqual(new Uint8Array([0xfc]));
    expect(decodeCompact(new Uint8Array([0xfc]))).toEqual([63n, 1]);
  });

  it("encodes and decodes mode 1 lower bound", () => {
    expect(encodeCompact(64n)).toEqual(new Uint8Array([0x01, 0x01]));
    expect(decodeCompact(new Uint8Array([0x01, 0x01]))).toEqual([64n, 2]);
  });

  it("encodes and decodes mode 1 upper bound", () => {
    const encoded = encodeCompact(16_383n);
    expect(decodeCompact(encoded)).toEqual([16_383n, 2]);
  });

  it("encodes and decodes mode 2 lower bound", () => {
    const encoded = encodeCompact(16_384n);
    expect(decodeCompact(encoded)).toEqual([16_384n, 4]);
  });

  it("encodes and decodes mode 2 upper bound", () => {
    const encoded = encodeCompact((1n << 30n) - 1n);
    expect(decodeCompact(encoded)).toEqual([(1n << 30n) - 1n, 4]);
  });

  it("encodes and decodes big-int mode at 2^30", () => {
    const v = 1n << 30n;
    const decoded = decodeCompact(encodeCompact(v));
    expect(decoded?.[0]).toEqual(v);
  });

  it("encodes and decodes big-int mode at u64 max", () => {
    const v = (1n << 64n) - 1n;
    const decoded = decodeCompact(encodeCompact(v));
    expect(decoded?.[0]).toEqual(v);
  });

  it("round trips across all probe values", () => {
    const probes: bigint[] = [
      0n,
      1n,
      63n,
      64n,
      100n,
      16_383n,
      16_384n,
      1n << 20n,
      (1n << 30n) - 1n,
      1n << 30n,
      1n << 32n,
      (1n << 64n) - 1n,
    ];
    for (const v of probes) {
      const decoded = decodeCompact(encodeCompact(v));
      expect(decoded?.[0]).toEqual(v);
    }
  });

  it("returns null on empty input", () => {
    expect(decodeCompact(new Uint8Array())).toBeNull();
  });

  it("returns null on truncated mode 1", () => {
    expect(decodeCompact(new Uint8Array([0x01]))).toBeNull();
  });

  it("returns null on truncated mode 2", () => {
    expect(decodeCompact(new Uint8Array([0x02, 0x00, 0x00]))).toBeNull();
  });

  it("returns null on truncated big-int mode", () => {
    expect(decodeCompact(new Uint8Array([0x03, 0x01]))).toBeNull();
  });

  it("decodes a length-prefixed byte vector", () => {
    const wire = new Uint8Array([
      ...encodeCompact(5n),
      ...new TextEncoder().encode("hello"),
    ]);
    const result = decodeBytes(wire);
    expect(result).not.toBeNull();
    if (result === null) return;
    expect(new TextDecoder().decode(result[0])).toEqual("hello");
    expect(result[1]).toEqual(6);
  });

  it("returns null on truncated payload", () => {
    const wire = new Uint8Array([
      ...encodeCompact(10n),
      ...new TextEncoder().encode("only5"),
    ]);
    expect(decodeBytes(wire)).toBeNull();
  });

  it("matches the e2e scale-vectors fixture", () => {
    for (const c of fixture.compact) {
      const value = BigInt(c.value);
      const expected = unhex(c.encoded);
      expect(encodeCompact(value)).toEqual(expected);
      const decoded = decodeCompact(expected);
      expect(decoded).not.toBeNull();
      if (decoded === null) continue;
      expect(decoded[0]).toEqual(value);
      expect(decoded[1]).toEqual(c.consumed);
    }
  });
});
