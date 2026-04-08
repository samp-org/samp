import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  type ChainParams,
  ExtrinsicError,
  buildSignedExtrinsic,
  extractCall,
  extractSigner,
} from "../src/extrinsic.js";
import { decodeCompact, encodeCompact } from "../src/scale.js";

const fixture = JSON.parse(
  readFileSync(resolve(__dirname, "../../e2e/extrinsic-vectors.json"), "utf-8"),
);

const ALICE_PUBLIC_KEY = unhex(
  "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
);
const FIXED_SIGNATURE = new Uint8Array(64).fill(0xab);

function unhex(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s.replace(/^0x/, ""), "hex"));
}

function fixedSigner(_msg: Uint8Array): Uint8Array {
  return FIXED_SIGNATURE;
}

function makeChainParams(): ChainParams {
  return {
    genesisHash: new Uint8Array(32).fill(0x11),
    specVersion: 100,
    txVersion: 1,
  };
}

function buildRemarkArgs(remark: Uint8Array): Uint8Array {
  const len = encodeCompact(BigInt(remark.length));
  const out = new Uint8Array(len.length + remark.length);
  out.set(len, 0);
  out.set(remark, len.length);
  return out;
}

describe("extrinsic", () => {
  it("round trips through extract", () => {
    const args = buildRemarkArgs(new TextEncoder().encode("hello bob"));
    const ext = buildSignedExtrinsic(0, 7, args, ALICE_PUBLIC_KEY, fixedSigner, 0, makeChainParams());

    const signer = extractSigner(ext);
    expect(signer).not.toBeNull();
    expect(signer).toEqual(ALICE_PUBLIC_KEY);

    const extracted = extractCall(ext);
    expect(extracted).not.toBeNull();
    if (extracted === null) return;
    expect(extracted.pallet).toEqual(0);
    expect(extracted.call).toEqual(7);
    expect(extracted.args).toEqual(args);
  });

  it("starts with a compact length prefix", () => {
    const args = buildRemarkArgs(new TextEncoder().encode("x"));
    const ext = buildSignedExtrinsic(0, 7, args, ALICE_PUBLIC_KEY, fixedSigner, 0, makeChainParams());
    const decoded = decodeCompact(ext);
    expect(decoded).not.toBeNull();
    if (decoded === null) return;
    const [declaredLen, prefixLen] = decoded;
    expect(Number(declaredLen) + prefixLen).toEqual(ext.length);
  });

  it("uses immortal era byte", () => {
    const args = buildRemarkArgs(new TextEncoder().encode("x"));
    const ext = buildSignedExtrinsic(0, 7, args, ALICE_PUBLIC_KEY, fixedSigner, 0, makeChainParams());
    const decoded = decodeCompact(ext);
    if (decoded === null) throw new Error("expected prefix");
    const payload = ext.subarray(decoded[1]);
    const eraOffset = 1 + 1 + 32 + 1 + 64;
    expect(payload[eraOffset]).toEqual(0x00);
  });

  it("different nonces produce different bytes", () => {
    const args = buildRemarkArgs(new TextEncoder().encode("x"));
    const cp = makeChainParams();
    const a = buildSignedExtrinsic(0, 7, args, ALICE_PUBLIC_KEY, fixedSigner, 0, cp);
    const b = buildSignedExtrinsic(0, 7, args, ALICE_PUBLIC_KEY, fixedSigner, 1, cp);
    expect(a).not.toEqual(b);
  });

  it("returns null when extracting signer from unsigned extrinsic", () => {
    const unsigned = new Uint8Array([0x10, 0x04, 0x03, 0x00, 0x00]);
    expect(extractSigner(unsigned)).toBeNull();
  });

  it("returns null when extracting call from unsigned extrinsic", () => {
    const unsigned = new Uint8Array([0x10, 0x04, 0x03, 0x00, 0x00]);
    expect(extractCall(unsigned)).toBeNull();
  });

  it("returns null when extracting signer from empty input", () => {
    expect(extractSigner(new Uint8Array())).toBeNull();
  });

  it("hashes payloads larger than 256 bytes via blake2b", () => {
    const bigRemark = new Uint8Array(1024).fill(0xab);
    const args = buildRemarkArgs(bigRemark);
    const captured: number[] = [];
    const capturingSigner = (msg: Uint8Array) => {
      captured.push(msg.length);
      return FIXED_SIGNATURE;
    };
    const ext = buildSignedExtrinsic(
      0,
      7,
      args,
      ALICE_PUBLIC_KEY,
      capturingSigner,
      0,
      makeChainParams(),
    );
    expect(captured).toEqual([32]);
    const extracted = extractCall(ext);
    expect(extracted).not.toBeNull();
    if (extracted === null) return;
    expect(extracted.args).toEqual(args);
  });

  it("rejects wrong public key length", () => {
    expect(() =>
      buildSignedExtrinsic(
        0,
        7,
        new Uint8Array(),
        new Uint8Array(31),
        fixedSigner,
        0,
        makeChainParams(),
      ),
    ).toThrow(ExtrinsicError);
  });

  it("matches the e2e extrinsic-vectors fixture", () => {
    for (const c of fixture.cases) {
      const publicKey = unhex(c.public_key);
      const signature = unhex(c.fixed_signature);
      const callArgs = unhex(c.call_args);
      const chain: ChainParams = {
        genesisHash: unhex(c.chain_params.genesis_hash),
        specVersion: c.chain_params.spec_version,
        txVersion: c.chain_params.tx_version,
      };
      const built = buildSignedExtrinsic(
        c.pallet_idx,
        c.call_idx,
        callArgs,
        publicKey,
        () => signature,
        c.nonce,
        chain,
      );
      expect(built).toEqual(unhex(c.expected_extrinsic));
    }
  });
});
