import { sha512 } from "@noble/hashes/sha512";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/abstract/utils";
import { SampError } from "./error.js";
import { Remark } from "./wire.js";

function getCurveOrder(): bigint {
  return BigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989");
}

function mod(n: bigint, m: bigint): bigint {
  return ((n % m) + m) % m;
}

export const ENCRYPTED_OVERHEAD = 80;

function divideScalarByCofactor(s: Uint8Array): void {
  let low = 0;
  for (let i = s.length - 1; i >= 0; i--) {
    const r = s[i] & 0x07;
    s[i] = (s[i] >>> 3) + low;
    low = r << 5;
  }
}

export function sr25519SigningScalar(seed: Uint8Array): bigint {
  const h = sha512(seed);
  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;
  const key = h.slice(0, 32);
  divideScalarByCofactor(key);
  const n = bytesToNumberLE(key);
  return mod(n, getCurveOrder());
}

export function publicFromSeed(seed: Uint8Array): Uint8Array {
  const scalar = sr25519SigningScalar(seed);
  return RistrettoPoint.BASE.multiply(scalar).toRawBytes();
}

function hkdfExpand(ikm: Uint8Array, salt: Uint8Array | undefined, info: Uint8Array, length: number): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

function deriveEphemeral(seed: Uint8Array, recipient: Uint8Array, nonce: Uint8Array): Uint8Array {
  const info = new Uint8Array(44);
  info.set(recipient, 0);
  info.set(nonce, 32);
  return hkdfExpand(seed, undefined, info, 32);
}

function deriveSealKey(seed: Uint8Array, nonce: Uint8Array): Uint8Array {
  return hkdfExpand(seed, nonce, new TextEncoder().encode("samp-seal"), 32);
}

function deriveSymmetricKey(sharedSecret: Uint8Array, nonce: Uint8Array): Uint8Array {
  return hkdfExpand(sharedSecret, nonce, new TextEncoder().encode("samp-message"), 32);
}

function deriveViewTag(sharedSecret: Uint8Array): number {
  return hkdfExpand(sharedSecret, undefined, new TextEncoder().encode("samp-view-tag"), 1)[0];
}

function scalarFromBytes(b: Uint8Array): bigint {
  const n = bytesToNumberLE(b);
  return mod(n, getCurveOrder());
}

function ecdhSharedSecret(scalar: bigint, pointBytes: Uint8Array): Uint8Array {
  const point = RistrettoPoint.fromHex(pointBytes);
  return point.multiply(scalar).toRawBytes();
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function scalarToBytes32(s: bigint): Uint8Array {
  return numberToBytesLE(s, 32);
}

export function encrypt(
  plaintext: Uint8Array,
  recipientPub: Uint8Array,
  nonce: Uint8Array,
  senderSeed: Uint8Array,
): Uint8Array {
  const ephBytes = deriveEphemeral(senderSeed, recipientPub, nonce);
  const ephScalar = scalarFromBytes(ephBytes);
  const ephPubkey = RistrettoPoint.BASE.multiply(ephScalar).toRawBytes();

  const sharedSecret = ecdhSharedSecret(ephScalar, recipientPub);
  const sealKey = deriveSealKey(senderSeed, nonce);
  const sealedTo = xorBytes(recipientPub, sealKey);
  const symKey = deriveSymmetricKey(sharedSecret, nonce);

  const cipher = chacha20poly1305(symKey, nonce, sealedTo);
  const ciphertextWithTag = cipher.encrypt(plaintext);

  const out = new Uint8Array(ENCRYPTED_OVERHEAD + plaintext.length);
  out.set(ephPubkey, 0);
  out.set(sealedTo, 32);
  out.set(ciphertextWithTag, 64);
  return out;
}

export function decrypt(remark: Remark, signingScalar: bigint): Uint8Array {
  ensureOneToOneRemark(remark);
  const content = remark.content;
  const sharedSecret = ecdhSharedSecret(signingScalar, content.slice(0, 32));
  const sealedTo = content.slice(32, 64);
  const symKey = deriveSymmetricKey(sharedSecret, remark.nonce);
  const cipher = chacha20poly1305(symKey, remark.nonce, sealedTo);
  try {
    return cipher.decrypt(content.slice(64));
  } catch {
    throw new SampError("decryption failed");
  }
}

export function decryptAsSender(remark: Remark, senderSeed: Uint8Array): Uint8Array {
  ensureOneToOneRemark(remark);
  const content = remark.content;
  const sealKey = deriveSealKey(senderSeed, remark.nonce);
  const recipient = xorBytes(content.slice(32, 64), sealKey);

  const ephBytes = deriveEphemeral(senderSeed, recipient, remark.nonce);
  const ephScalar = scalarFromBytes(ephBytes);
  const sharedSecret = ecdhSharedSecret(ephScalar, recipient);

  const symKey = deriveSymmetricKey(sharedSecret, remark.nonce);
  const sealedTo = content.slice(32, 64);
  const cipher = chacha20poly1305(symKey, remark.nonce, sealedTo);
  try {
    return cipher.decrypt(content.slice(64));
  } catch {
    throw new SampError("decryption failed");
  }
}

function ensureOneToOneRemark(remark: Remark): void {
  if (remark.content.length < ENCRYPTED_OVERHEAD) throw new SampError("insufficient data");
}

export function computeViewTag(
  senderSeed: Uint8Array,
  recipientPub: Uint8Array,
  nonce: Uint8Array,
): number {
  const ephBytes = deriveEphemeral(senderSeed, recipientPub, nonce);
  const ephScalar = scalarFromBytes(ephBytes);
  const sharedSecret = ecdhSharedSecret(ephScalar, recipientPub);
  return deriveViewTag(sharedSecret);
}

export function checkViewTag(remark: Remark, signingScalar: bigint): number {
  ensureOneToOneRemark(remark);
  const sharedSecret = ecdhSharedSecret(signingScalar, remark.content.slice(0, 32));
  return deriveViewTag(sharedSecret);
}

export function unsealRecipient(remark: Remark, senderSeed: Uint8Array): Uint8Array {
  ensureOneToOneRemark(remark);
  const sealKey = deriveSealKey(senderSeed, remark.nonce);
  return xorBytes(remark.content.slice(32, 64), sealKey);
}

const GROUP_EPH_INFO = new TextEncoder().encode("samp-group-eph");
const KEY_WRAP_INFO = new TextEncoder().encode("samp-key-wrap");
const CAPSULE_SIZE = 33;

export function deriveGroupEphemeral(senderSeed: Uint8Array, nonce: Uint8Array): Uint8Array {
  const info = new Uint8Array(GROUP_EPH_INFO.length + nonce.length);
  info.set(GROUP_EPH_INFO, 0);
  info.set(nonce, GROUP_EPH_INFO.length);
  const okm = hkdfExpand(senderSeed, undefined, info, 32);
  const scalar = scalarFromBytes(okm);
  return scalarToBytes32(scalar);
}

function deriveKeyWrap(sharedSecret: Uint8Array, nonce: Uint8Array): Uint8Array {
  return hkdfExpand(sharedSecret, nonce, KEY_WRAP_INFO, 32);
}

function xor32(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function buildCapsules(
  contentKey: Uint8Array,
  memberPubkeys: Uint8Array[],
  ephScalar: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  const scalar = bytesToNumberLE(ephScalar);
  const scalMod = mod(scalar, getCurveOrder());
  const out = new Uint8Array(memberPubkeys.length * CAPSULE_SIZE);
  for (let i = 0; i < memberPubkeys.length; i++) {
    const shared = ecdhSharedSecret(scalMod, memberPubkeys[i]);
    const tag = deriveViewTag(shared);
    const kek = deriveKeyWrap(shared, nonce);
    const wrapped = xor32(contentKey, kek);
    out[i * CAPSULE_SIZE] = tag;
    out.set(wrapped, i * CAPSULE_SIZE + 1);
  }
  return out;
}

export function scanCapsules(
  data: Uint8Array,
  ephPubkey: Uint8Array,
  myScalar: bigint,
  nonce: Uint8Array,
): { index: number; contentKey: Uint8Array } | null {
  const shared = ecdhSharedSecret(myScalar, ephPubkey);
  const myTag = deriveViewTag(shared);
  const kek = deriveKeyWrap(shared, nonce);

  let offset = 0;
  let idx = 0;
  while (offset + CAPSULE_SIZE <= data.length) {
    if (data[offset] === myTag) {
      const wrapped = data.slice(offset + 1, offset + 33);
      const contentKey = xor32(wrapped, kek);
      return { index: idx, contentKey };
    }
    offset += CAPSULE_SIZE;
    idx += 1;
  }
  return null;
}

export function encryptForGroup(
  plaintext: Uint8Array,
  memberPubkeys: Uint8Array[],
  nonce: Uint8Array,
  senderSeed: Uint8Array,
): { ephPubkey: Uint8Array; capsules: Uint8Array; ciphertext: Uint8Array } {
  const ephBytes = deriveGroupEphemeral(senderSeed, nonce);
  const ephScalar = scalarFromBytes(ephBytes);
  const ephPubkey = RistrettoPoint.BASE.multiply(ephScalar).toRawBytes();

  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  const capsules = buildCapsules(contentKey, memberPubkeys, ephBytes, nonce);

  const cipher = chacha20poly1305(contentKey, nonce);
  const ciphertext = cipher.encrypt(plaintext);

  return { ephPubkey, capsules, ciphertext };
}

export function decryptFromGroup(
  content: Uint8Array,
  myScalar: bigint,
  nonce: Uint8Array,
  knownN?: number,
): Uint8Array {
  if (content.length < 32) throw new SampError("insufficient data");
  const ephPubkey = content.slice(0, 32);
  const afterEph = content.slice(32);

  const result = scanCapsules(afterEph, ephPubkey, myScalar, nonce);
  if (!result) throw new SampError("decryption failed");
  const { index: capsuleIdx, contentKey } = result;

  if (knownN !== undefined) {
    const ctStart = knownN * CAPSULE_SIZE;
    if (ctStart > afterEph.length) throw new SampError("insufficient data");
    const cipher = chacha20poly1305(contentKey, nonce);
    try {
      return cipher.decrypt(afterEph.slice(ctStart));
    } catch {
      throw new SampError("decryption failed");
    }
  }

  const minN = capsuleIdx + 1;
  const maxN = Math.floor((afterEph.length - 16) / CAPSULE_SIZE);
  for (let n = minN; n <= maxN; n++) {
    const ctStart = n * CAPSULE_SIZE;
    if (ctStart >= afterEph.length) break;
    const cipher = chacha20poly1305(contentKey, nonce);
    try {
      return cipher.decrypt(afterEph.slice(ctStart));
    } catch {
      continue;
    }
  }
  throw new SampError("decryption failed");
}
