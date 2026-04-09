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

function encode(pubkey: Pubkey, prefix: Ss58Prefix): Ss58Address {
  const payload = new Uint8Array(1 + 32);
  payload[0] = Ss58Prefix.get(prefix);
  payload.set(pubkey, 1);
  const sum = ss58Checksum(payload);
  const full = new Uint8Array(35);
  full.set(payload, 0);
  full[33] = sum[0] ?? 0;
  full[34] = sum[1] ?? 0;
  return Ss58Address.fromParts(bs58Encode(full), pubkey, prefix);
}

function parse(s: string): Ss58Address {
  const decoded = bs58Decode(s);
  if (decoded === null) throw new SampError("ss58 invalid base58");
  if (decoded.length < 35) throw new SampError("ss58 too short");
  const prefixByte = decoded[0];
  if (prefixByte === undefined || prefixByte >= 64) {
    throw new SampError(`ss58 prefix unsupported: ${prefixByte ?? -1}`);
  }
  const payload = decoded.subarray(0, 33);
  const expected = decoded.subarray(33, 35);
  const sum = ss58Checksum(payload);
  if (sum[0] !== expected[0] || sum[1] !== expected[1]) {
    throw new SampError("ss58 bad checksum");
  }
  const pubkey = Pubkey.fromBytes(decoded.slice(1, 33));
  const prefix = Ss58Prefix.from(prefixByte);
  return Ss58Address.fromParts(s, pubkey, prefix);
}

__registerSs58(parse, encode);
