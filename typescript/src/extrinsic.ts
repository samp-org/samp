import { blake2b } from "@noble/hashes/blake2b";

import { decodeCompact, encodeCompact } from "./scale.js";

const EXT_VERSION_SIGNED = 0x84;
const ADDR_TYPE_ID = 0x00;
const SIG_TYPE_SR25519 = 0x01;
const ERA_IMMORTAL = 0x00;
const METADATA_HASH_DISABLED = 0x00;
const SIGNED_HEADER_LEN = 99;
const MIN_SIGNED_EXTRINSIC = 103;
const MIN_SIGNER_PAYLOAD = 34;

export class ExtrinsicError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExtrinsicError";
  }
}

export interface ChainParams {
  genesisHash: Uint8Array;
  specVersion: number;
  txVersion: number;
}

export interface ExtractedCall {
  pallet: number;
  call: number;
  args: Uint8Array;
}

export type SignFn = (msg: Uint8Array) => Uint8Array;

function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function u32LE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = value & 0xff;
  out[1] = (value >>> 8) & 0xff;
  out[2] = (value >>> 16) & 0xff;
  out[3] = (value >>> 24) & 0xff;
  return out;
}

export function buildSignedExtrinsic(
  palletIdx: number,
  callIdx: number,
  callArgs: Uint8Array,
  publicKey: Uint8Array,
  sign: SignFn,
  nonce: number,
  chainParams: ChainParams,
): Uint8Array {
  if (publicKey.length !== 32) {
    throw new ExtrinsicError(`public_key must be 32 bytes, got ${publicKey.length}`);
  }
  if (chainParams.genesisHash.length !== 32) {
    throw new ExtrinsicError(
      `genesis_hash must be 32 bytes, got ${chainParams.genesisHash.length}`,
    );
  }

  const callData = concat(new Uint8Array([palletIdx, callIdx]), callArgs);
  const tip = new Uint8Array([0]);

  const signingPayload = concat(
    callData,
    new Uint8Array([ERA_IMMORTAL]),
    encodeCompact(BigInt(nonce)),
    tip,
    new Uint8Array([METADATA_HASH_DISABLED]),
    u32LE(chainParams.specVersion),
    u32LE(chainParams.txVersion),
    chainParams.genesisHash,
    chainParams.genesisHash,
    new Uint8Array([0x00]),
  );

  const toSign =
    signingPayload.length > 256 ? blake2b(signingPayload, { dkLen: 32 }) : signingPayload;

  const signature = sign(toSign);
  if (signature.length !== 64) {
    throw new ExtrinsicError(`signature must be 64 bytes, got ${signature.length}`);
  }

  const extrinsicPayload = concat(
    new Uint8Array([EXT_VERSION_SIGNED, ADDR_TYPE_ID]),
    publicKey,
    new Uint8Array([SIG_TYPE_SR25519]),
    signature,
    new Uint8Array([ERA_IMMORTAL]),
    encodeCompact(BigInt(nonce)),
    tip,
    new Uint8Array([METADATA_HASH_DISABLED]),
    callData,
  );

  return concat(encodeCompact(BigInt(extrinsicPayload.length)), extrinsicPayload);
}

export function extractSigner(extrinsicBytes: Uint8Array): Uint8Array | null {
  const decoded = decodeCompact(extrinsicBytes);
  if (decoded === null) return null;
  const [, prefixLen] = decoded;
  const payload = extrinsicBytes.subarray(prefixLen);
  if (
    payload.length < MIN_SIGNER_PAYLOAD ||
    (payload[0] & 0x80) === 0 ||
    payload[1] !== ADDR_TYPE_ID
  ) {
    return null;
  }
  return payload.subarray(2, 34);
}

export function extractCall(extrinsicBytes: Uint8Array): ExtractedCall | null {
  const decoded = decodeCompact(extrinsicBytes);
  if (decoded === null) return null;
  const [, prefixLen] = decoded;
  const payload = extrinsicBytes.subarray(prefixLen);

  if (payload.length < MIN_SIGNED_EXTRINSIC || (payload[0] & 0x80) === 0) {
    return null;
  }

  let offset = SIGNED_HEADER_LEN;
  if (offset >= payload.length) return null;
  if (payload[offset] !== 0x00) {
    offset += 2;
  } else {
    offset += 1;
  }

  const nonceDecode = decodeCompact(payload.subarray(offset));
  if (nonceDecode === null) return null;
  offset += nonceDecode[1];

  const tipDecode = decodeCompact(payload.subarray(offset));
  if (tipDecode === null) return null;
  offset += tipDecode[1];

  offset += 1;

  if (offset + 2 > payload.length) return null;
  const pallet = payload[offset];
  const call = payload[offset + 1];
  offset += 2;

  if (offset > payload.length) return null;

  return { pallet, call, args: payload.subarray(offset) };
}
