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
import {
  CallArgs,
  CallIdx,
  ExtrinsicBytes,
  ExtrinsicNonce,
  GenesisHash,
  PalletIdx,
  Pubkey,
  Signature,
  SpecVersion,
  TxVersion,
} from "../src/types.js";

const fixture = JSON.parse(
  readFileSync(resolve(__dirname, "../../e2e/extrinsic-vectors.json"), "utf-8"),
);

const ALICE_PUBLIC_KEY = Pubkey.fromBytes(
  unhex("0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"),
);
const FIXED_SIGNATURE = Signature.fromBytes(new Uint8Array(64).fill(0xab));

function unhex(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s.replace(/^0x/, ""), "hex"));
}

function fixedSigner(_msg: Uint8Array): Signature {
  return FIXED_SIGNATURE;
}

function makeChainParams(): ChainParams {
  return {
    genesisHash: GenesisHash.fromBytes(new Uint8Array(32).fill(0x11)),
    specVersion: SpecVersion.from(100),
    txVersion: TxVersion.from(1),
  };
}

function buildRemarkArgs(remark: Uint8Array): CallArgs {
  const len = encodeCompact(BigInt(remark.length));
  const out = new Uint8Array(len.length + remark.length);
  out.set(len, 0);
  out.set(remark, len.length);
  return CallArgs.fromBytes(out);
}

describe("extrinsic", () => {
  it("round trips through extract", () => {
    const args = buildRemarkArgs(new TextEncoder().encode("hello bob"));
    const ext = buildSignedExtrinsic(
      PalletIdx.from(0),
      CallIdx.from(7),
      args,
      ALICE_PUBLIC_KEY,
      fixedSigner,
      ExtrinsicNonce.from(0),
      makeChainParams(),
    );

    const signer = extractSigner(ext);
    expect(signer).not.toBeNull();
    expect(signer).toEqual(ALICE_PUBLIC_KEY);

    const extracted = extractCall(ext);
    expect(extracted).not.toBeNull();
    if (extracted === null) return;
    expect(PalletIdx.get(extracted.pallet)).toEqual(0);
    expect(CallIdx.get(extracted.call)).toEqual(7);
    expect(CallArgs.asBytes(extracted.args)).toEqual(CallArgs.asBytes(args));
  });

  it("starts with a compact length prefix", () => {
    const args = buildRemarkArgs(new TextEncoder().encode("x"));
    const ext = buildSignedExtrinsic(
      PalletIdx.from(0),
      CallIdx.from(7),
      args,
      ALICE_PUBLIC_KEY,
      fixedSigner,
      ExtrinsicNonce.from(0),
      makeChainParams(),
    );
    const decoded = decodeCompact(ExtrinsicBytes.asBytes(ext));
    expect(decoded).not.toBeNull();
    if (decoded === null) return;
    const [declaredLen, prefixLen] = decoded;
    expect(Number(declaredLen) + prefixLen).toEqual(ExtrinsicBytes.asBytes(ext).length);
  });

  it("uses immortal era byte", () => {
    const args = buildRemarkArgs(new TextEncoder().encode("x"));
    const ext = buildSignedExtrinsic(
      PalletIdx.from(0),
      CallIdx.from(7),
      args,
      ALICE_PUBLIC_KEY,
      fixedSigner,
      ExtrinsicNonce.from(0),
      makeChainParams(),
    );
    const bytes = ExtrinsicBytes.asBytes(ext);
    const decoded = decodeCompact(bytes);
    if (decoded === null) throw new Error("expected prefix");
    const payload = bytes.subarray(decoded[1]);
    const eraOffset = 1 + 1 + 32 + 1 + 64;
    expect(payload[eraOffset]).toEqual(0x00);
  });

  it("different nonces produce different bytes", () => {
    const args = buildRemarkArgs(new TextEncoder().encode("x"));
    const cp = makeChainParams();
    const a = buildSignedExtrinsic(
      PalletIdx.from(0),
      CallIdx.from(7),
      args,
      ALICE_PUBLIC_KEY,
      fixedSigner,
      ExtrinsicNonce.from(0),
      cp,
    );
    const b = buildSignedExtrinsic(
      PalletIdx.from(0),
      CallIdx.from(7),
      args,
      ALICE_PUBLIC_KEY,
      fixedSigner,
      ExtrinsicNonce.from(1),
      cp,
    );
    expect(ExtrinsicBytes.asBytes(a)).not.toEqual(ExtrinsicBytes.asBytes(b));
  });

  it("returns null when extracting signer from unsigned extrinsic", () => {
    const unsigned = ExtrinsicBytes.fromBytes(new Uint8Array([0x10, 0x04, 0x03, 0x00, 0x00]));
    expect(extractSigner(unsigned)).toBeNull();
  });

  it("returns null when extracting call from unsigned extrinsic", () => {
    const unsigned = ExtrinsicBytes.fromBytes(new Uint8Array([0x10, 0x04, 0x03, 0x00, 0x00]));
    expect(extractCall(unsigned)).toBeNull();
  });

  it("returns null when extracting signer from empty input", () => {
    expect(extractSigner(ExtrinsicBytes.fromBytes(new Uint8Array()))).toBeNull();
  });

  it("hashes payloads larger than 256 bytes via blake2b", () => {
    const bigRemark = new Uint8Array(1024).fill(0xab);
    const args = buildRemarkArgs(bigRemark);
    const captured: number[] = [];
    const capturingSigner = (msg: Uint8Array): Signature => {
      captured.push(msg.length);
      return FIXED_SIGNATURE;
    };
    const ext = buildSignedExtrinsic(
      PalletIdx.from(0),
      CallIdx.from(7),
      args,
      ALICE_PUBLIC_KEY,
      capturingSigner,
      ExtrinsicNonce.from(0),
      makeChainParams(),
    );
    expect(captured).toEqual([32]);
    const extracted = extractCall(ext);
    expect(extracted).not.toBeNull();
    if (extracted === null) return;
    expect(CallArgs.asBytes(extracted.args)).toEqual(CallArgs.asBytes(args));
  });

  it("rejects wrong public key length", () => {
    expect(() => Pubkey.fromBytes(new Uint8Array(31))).toThrow(/pubkey must be 32 bytes/);
  });

  it("rejects wrong signature length", () => {
    const badSigner = (_msg: Uint8Array): Signature => {
      return new Uint8Array(63) as Signature;
    };
    expect(() =>
      buildSignedExtrinsic(
        PalletIdx.from(0),
        CallIdx.from(7),
        CallArgs.fromBytes(new Uint8Array()),
        ALICE_PUBLIC_KEY,
        badSigner,
        ExtrinsicNonce.from(0),
        makeChainParams(),
      ),
    ).toThrow(ExtrinsicError);
  });

  it("matches the e2e extrinsic-vectors fixture", () => {
    for (const c of fixture.cases) {
      const publicKey = Pubkey.fromBytes(unhex(c.public_key));
      const signature = Signature.fromBytes(unhex(c.fixed_signature));
      const callArgs = CallArgs.fromBytes(unhex(c.call_args));
      const chain: ChainParams = {
        genesisHash: GenesisHash.fromBytes(unhex(c.chain_params.genesis_hash)),
        specVersion: SpecVersion.from(c.chain_params.spec_version),
        txVersion: TxVersion.from(c.chain_params.tx_version),
      };
      const built = buildSignedExtrinsic(
        PalletIdx.from(c.pallet_idx),
        CallIdx.from(c.call_idx),
        callArgs,
        publicKey,
        () => signature,
        ExtrinsicNonce.from(c.nonce),
        chain,
      );
      expect(ExtrinsicBytes.asBytes(built)).toEqual(unhex(c.expected_extrinsic));
    }
  });
});
