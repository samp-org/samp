import { blake2b } from "@noble/hashes/blake2b";
import { SampError } from "./error.js";
import { Pubkey, Ss58Address, Ss58Prefix, __registerSs58 } from "./types.js";

const SS58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const SS58PRE = new TextEncoder().encode("SS58PRE");

function bs58Encode(data: Uint8Array): string {
  if (data.length === 0) return "";
  const digits: number[] = [0];
  for (const b of data) {
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
  let out = "";
  for (const b of data) {
    if (b === 0) out += SS58_ALPHABET[0];
    else break;
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    const d = digits[i] ?? 0;
    out += SS58_ALPHABET[d];
  }
  return out;
}

function bs58Decode(input: string): Uint8Array | null {
  let bytes: number[] = [0];
  for (const ch of input) {
    const code = ch.charCodeAt(0);
    if (code > 127) return null;
    const idx = SS58_ALPHABET.indexOf(ch);
    if (idx < 0) return null;
    let carry = idx;
    for (let i = 0; i < bytes.length; i++) {
      carry += (bytes[i] ?? 0) * 58;
      bytes[i] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    while (carry > 0) {
      bytes.push(carry % 256);
      carry = Math.floor(carry / 256);
    }
  }
  for (const ch of input) {
    if (ch === "1") bytes.push(0);
    else break;
  }
  bytes.reverse();
  return Uint8Array.from(bytes);
}

function ss58Checksum(payload: Uint8Array): Uint8Array {
  const h = blake2b.create({ dkLen: 64 });
  h.update(SS58PRE);
  h.update(payload);
  return h.digest();
}

function encodePrefix(prefix: Ss58Prefix): Uint8Array {
  const value = Ss58Prefix.get(prefix);
  if (value < 64) return new Uint8Array([value]);
  return new Uint8Array([
    ((value & 0b0000_0000_1111_1100) >> 2) | 0b0100_0000,
    (value >> 8) | ((value & 0b0000_0000_0000_0011) << 6),
  ]);
}

function decodePrefix(decoded: Uint8Array): [number, number] {
  const first = decoded[0]!;
  if ((first & 0b1000_0000) !== 0) {
    throw new SampError(`ss58 prefix unsupported: ${first}`);
  }
  if ((first & 0b0100_0000) === 0) return [first, 1];
  const second = decoded[1]!;
  return [
    ((first & 0b0011_1111) << 2) | (second >> 6) | ((second & 0b0011_1111) << 8),
    2,
  ];
}

function encode(pubkey: Pubkey, prefix: Ss58Prefix): Ss58Address {
  const prefixBytes = encodePrefix(prefix);
  const payload = new Uint8Array(prefixBytes.length + 32);
  payload.set(prefixBytes, 0);
  payload.set(pubkey, prefixBytes.length);
  const sum = ss58Checksum(payload);
  const full = new Uint8Array(payload.length + 2);
  full.set(payload, 0);
  full[payload.length] = sum[0]!;
  full[payload.length + 1] = sum[1]!;
  return Ss58Address.fromParts(bs58Encode(full), pubkey, prefix);
}

function parse(s: string): Ss58Address {
  const decoded = bs58Decode(s);
  if (decoded === null) throw new SampError("ss58 invalid base58");
  if (decoded.length < 35) throw new SampError("ss58 too short");
  const [prefixValue, prefixLen] = decodePrefix(decoded);
  const pubkeyEnd = prefixLen + 32;
  if (decoded.length < pubkeyEnd + 2) throw new SampError("ss58 too short");
  if (decoded.length !== pubkeyEnd + 2) throw new SampError("ss58 bad checksum");
  const payload = decoded.subarray(0, pubkeyEnd);
  const expected = decoded.subarray(pubkeyEnd, pubkeyEnd + 2);
  const sum = ss58Checksum(payload);
  if (sum[0] !== expected[0] || sum[1] !== expected[1]) {
    throw new SampError("ss58 bad checksum");
  }
  const pubkey = Pubkey.fromBytes(decoded.slice(prefixLen, pubkeyEnd));
  const prefix = Ss58Prefix.from(prefixValue);
  return Ss58Address.fromParts(s, pubkey, prefix);
}

__registerSs58(parse, encode);
