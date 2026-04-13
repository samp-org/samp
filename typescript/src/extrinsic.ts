import { blake2b } from "@noble/hashes/blake2b";

import { decodeCompact, encodeCompact } from "./scale.js";
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
} from "./types.js";

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
  readonly genesisHash: GenesisHash;
  readonly specVersion: SpecVersion;
  readonly txVersion: TxVersion;
}

export interface ExtractedCall {
  readonly pallet: PalletIdx;
  readonly call: CallIdx;
  readonly args: CallArgs;
}

export type SignFn = (msg: Uint8Array) => Signature;

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
  pallet: PalletIdx,
  call: CallIdx,
  args: CallArgs,
  publicKey: Pubkey,
  sign: SignFn,
  nonce: ExtrinsicNonce,
  chain: ChainParams,
): ExtrinsicBytes {
  const argBytes = CallArgs.asBytes(args);
  const callData = concat(new Uint8Array([PalletIdx.get(pallet), CallIdx.get(call)]), argBytes);
  const tip = new Uint8Array([0]);

  const signingPayload = concat(
    callData,
    new Uint8Array([ERA_IMMORTAL]),
    encodeCompact(BigInt(ExtrinsicNonce.get(nonce))),
    tip,
    new Uint8Array([METADATA_HASH_DISABLED]),
    u32LE(SpecVersion.get(chain.specVersion)),
    u32LE(TxVersion.get(chain.txVersion)),
    chain.genesisHash,
    chain.genesisHash,
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
    encodeCompact(BigInt(ExtrinsicNonce.get(nonce))),
    tip,
    new Uint8Array([METADATA_HASH_DISABLED]),
    callData,
  );

  return ExtrinsicBytes.fromBytes(
    concat(encodeCompact(BigInt(extrinsicPayload.length)), extrinsicPayload),
  );
}

export function extractSigner(extrinsicBytes: ExtrinsicBytes): Pubkey | null {
  // WHY: input boundary — payload is untrusted.
  const bytes = ExtrinsicBytes.asBytes(extrinsicBytes);
  const decoded = decodeCompact(bytes);
  if (decoded === null) return null;
  const [, prefixLen] = decoded;
  const payload = bytes.subarray(prefixLen);
  if (
    payload.length < MIN_SIGNER_PAYLOAD ||
    (payload[0]! & 0x80) === 0 ||
    payload[1] !== ADDR_TYPE_ID
  ) {
    return null;
  }
  return Pubkey.fromBytes(payload.slice(2, 34));
}

export function extractCall(extrinsicBytes: ExtrinsicBytes): ExtractedCall | null {
  // WHY: input boundary — payload is untrusted.
  const bytes = ExtrinsicBytes.asBytes(extrinsicBytes);
  const decoded = decodeCompact(bytes);
  if (decoded === null) return null;
  const [, prefixLen] = decoded;
  const payload = bytes.subarray(prefixLen);

  if (payload.length < MIN_SIGNED_EXTRINSIC || (payload[0]! & 0x80) === 0) {
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
  const pallet = PalletIdx.from(payload[offset]!);
  const call = CallIdx.from(payload[offset + 1]!);
  offset += 2;

  if (offset > payload.length) return null;

  return { pallet, call, args: CallArgs.fromBytes(payload.slice(offset)) };
}
