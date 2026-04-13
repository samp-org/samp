import { sha512 } from "@noble/hashes/sha512";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/abstract/utils";
import { SampError } from "./error.js";
import { ContentKey, Seed, ViewScalar } from "./secret.js";
import { Capsules, Ciphertext, EphPubkey, Nonce, Plaintext, Pubkey, Signature, ViewTag } from "./types.js";
import { sr25519KeypairFromSeed, sr25519Sign as wasmSr25519Sign } from "@polkadot/wasm-crypto";

export const ENCRYPTED_OVERHEAD = 80;
const CAPSULE_SIZE = 33;
const CURVE_ORDER = BigInt(
  "7237005577332262213973186563042994240857116359379907606001950938285454250989",
);

const MESSAGE_KEY_INFO = new TextEncoder().encode("samp-message");
const VIEW_TAG_INFO = new TextEncoder().encode("samp-view-tag");
const SEAL_INFO = new TextEncoder().encode("samp-seal");
const GROUP_EPH_INFO = new TextEncoder().encode("samp-group-eph");
const KEY_WRAP_INFO = new TextEncoder().encode("samp-key-wrap");

function mod(n: bigint, m: bigint): bigint {
  return ((n % m) + m) % m;
}

function divideScalarByCofactor(s: Uint8Array): void {
  let low = 0;
  for (let i = s.length - 1; i >= 0; i--) {
    const r = s[i]! & 0x07;
    s[i] = (s[i]! >>> 3) + low;
    low = r << 5;
  }
}

function hkdfExpand(ikm: Uint8Array, salt: Uint8Array | undefined, info: Uint8Array, length: number): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

function scalarFromBytes(b: Uint8Array): bigint {
  return mod(bytesToNumberLE(b), CURVE_ORDER);
}

function ecdhSharedSecret(scalar: bigint, pointBytes: Uint8Array): Uint8Array {
  return RistrettoPoint.fromHex(pointBytes).multiply(scalar).toRawBytes();
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

function deriveEphemeral(seed: Seed, recipient: Pubkey, nonce: Nonce): Uint8Array {
  const info = new Uint8Array(44);
  info.set(recipient, 0);
  info.set(Nonce.chachaBytes(nonce), 32);
  return hkdfExpand(Seed.exposeSecret(seed), undefined, info, 32);
}

function deriveSealKey(seed: Seed, nonce: Nonce): Uint8Array {
  return hkdfExpand(Seed.exposeSecret(seed), Nonce.chachaBytes(nonce), SEAL_INFO, 32);
}

function deriveSymmetricKey(sharedSecret: Uint8Array, nonce: Nonce): Uint8Array {
  return hkdfExpand(sharedSecret, Nonce.chachaBytes(nonce), MESSAGE_KEY_INFO, 32);
}

function deriveViewTagByte(sharedSecret: Uint8Array): number {
  return hkdfExpand(sharedSecret, undefined, VIEW_TAG_INFO, 1)[0]!;
}

function deriveKeyWrap(sharedSecret: Uint8Array, nonce: Nonce): Uint8Array {
  return hkdfExpand(sharedSecret, Nonce.chachaBytes(nonce), KEY_WRAP_INFO, 32);
}

// WHY: the single crypto boundary that turns a 32-byte ViewScalar into the
// bigint scalar the ristretto curve operations expect.
function viewScalarToBigInt(vs: ViewScalar): bigint {
  return mod(bytesToNumberLE(ViewScalar.exposeSecret(vs)), CURVE_ORDER);
}

export function sr25519Sign(seed: Seed, message: Uint8Array): Signature {
  const kp = sr25519KeypairFromSeed(Seed.exposeSecret(seed));
  const sig = wasmSr25519Sign(kp.slice(64, 96), kp.slice(0, 64), message);
  return Signature.fromBytes(sig);
}

export function sr25519SigningScalar(seed: Seed): ViewScalar {
  const raw = Seed.exposeSecret(seed);
  const h = sha512(raw);
  h[0]! &= 248;
  h[31]! &= 63;
  h[31]! |= 64;
  const key = h.slice(0, 32);
  divideScalarByCofactor(key);
  const scalar = mod(bytesToNumberLE(key), CURVE_ORDER);
  return ViewScalar.fromBytes(numberToBytesLE(scalar, 32));
}

export function publicFromSeed(seed: Seed): Pubkey {
  const scalar = sr25519SigningScalar(seed);
  const raw = RistrettoPoint.BASE.multiply(viewScalarToBigInt(scalar)).toRawBytes();
  return Pubkey.fromBytes(raw);
}

export function encrypt(
  plaintext: Plaintext,
  recipient: Pubkey,
  nonce: Nonce,
  senderSeed: Seed,
): Ciphertext {
  const ephBytes = deriveEphemeral(senderSeed, recipient, nonce);
  const ephScalar = scalarFromBytes(ephBytes);
  const ephPubkey = RistrettoPoint.BASE.multiply(ephScalar).toRawBytes();
  const sharedSecret = ecdhSharedSecret(ephScalar, recipient);
  const sealKey = deriveSealKey(senderSeed, nonce);
  const sealedTo = xor(recipient, sealKey);
  const symKey = deriveSymmetricKey(sharedSecret, nonce);
  const cipher = chacha20poly1305(symKey, Nonce.chachaBytes(nonce), sealedTo);
  const ptBytes = Plaintext.asBytes(plaintext);
  const ctWithTag = cipher.encrypt(ptBytes);
  const out = new Uint8Array(ENCRYPTED_OVERHEAD + ptBytes.length);
  out.set(ephPubkey, 0);
  out.set(sealedTo, 32);
  out.set(ctWithTag, 64);
  return Ciphertext.fromBytes(out);
}

export function decrypt(ciphertext: Ciphertext, nonce: Nonce, signingScalar: ViewScalar): Plaintext {
  const content = Ciphertext.asBytes(ciphertext);
  if (content.length < ENCRYPTED_OVERHEAD) throw new SampError("insufficient data");
  const sharedSecret = ecdhSharedSecret(viewScalarToBigInt(signingScalar), content.slice(0, 32));
  const sealedTo = content.slice(32, 64);
  const symKey = deriveSymmetricKey(sharedSecret, nonce);
  const cipher = chacha20poly1305(symKey, Nonce.chachaBytes(nonce), sealedTo);
  try {
    return Plaintext.fromBytes(cipher.decrypt(content.slice(64)));
  } catch {
    throw new SampError("decryption failed");
  }
}

export function decryptAsSender(ciphertext: Ciphertext, nonce: Nonce, senderSeed: Seed): Plaintext {
  const content = Ciphertext.asBytes(ciphertext);
  if (content.length < ENCRYPTED_OVERHEAD) throw new SampError("insufficient data");
  const sealKey = deriveSealKey(senderSeed, nonce);
  const recipientBytes = xor(content.slice(32, 64), sealKey);
  const recipient = Pubkey.fromBytes(recipientBytes);
  const ephBytes = deriveEphemeral(senderSeed, recipient, nonce);
  const ephScalar = scalarFromBytes(ephBytes);
  const sharedSecret = ecdhSharedSecret(ephScalar, recipient);
  const symKey = deriveSymmetricKey(sharedSecret, nonce);
  const sealedTo = content.slice(32, 64);
  const cipher = chacha20poly1305(symKey, Nonce.chachaBytes(nonce), sealedTo);
  try {
    return Plaintext.fromBytes(cipher.decrypt(content.slice(64)));
  } catch {
    throw new SampError("decryption failed");
  }
}

export function computeViewTag(senderSeed: Seed, recipient: Pubkey, nonce: Nonce): ViewTag {
  const ephBytes = deriveEphemeral(senderSeed, recipient, nonce);
  const ephScalar = scalarFromBytes(ephBytes);
  const sharedSecret = ecdhSharedSecret(ephScalar, recipient);
  return ViewTag.from(deriveViewTagByte(sharedSecret));
}

export function checkViewTag(ciphertext: Ciphertext, signingScalar: ViewScalar): ViewTag {
  const content = Ciphertext.asBytes(ciphertext);
  if (content.length < ENCRYPTED_OVERHEAD) throw new SampError("insufficient data");
  const sharedSecret = ecdhSharedSecret(viewScalarToBigInt(signingScalar), content.slice(0, 32));
  return ViewTag.from(deriveViewTagByte(sharedSecret));
}

export function unsealRecipient(ciphertext: Ciphertext, nonce: Nonce, senderSeed: Seed): Pubkey {
  const content = Ciphertext.asBytes(ciphertext);
  if (content.length < ENCRYPTED_OVERHEAD) throw new SampError("insufficient data");
  const sealKey = deriveSealKey(senderSeed, nonce);
  return Pubkey.fromBytes(xor(content.slice(32, 64), sealKey));
}

function deriveGroupEphemeralBytes(senderSeed: Seed, nonce: Nonce): Uint8Array {
  const info = new Uint8Array(GROUP_EPH_INFO.length + 12);
  info.set(GROUP_EPH_INFO, 0);
  info.set(Nonce.chachaBytes(nonce), GROUP_EPH_INFO.length);
  return hkdfExpand(Seed.exposeSecret(senderSeed), undefined, info, 32);
}

export function deriveGroupEphemeral(senderSeed: Seed, nonce: Nonce): Uint8Array {
  const bytes = deriveGroupEphemeralBytes(senderSeed, nonce);
  return numberToBytesLE(scalarFromBytes(bytes), 32);
}

export function buildCapsules(
  contentKey: ContentKey,
  memberPubkeys: Pubkey[],
  ephScalarBytes: Uint8Array,
  nonce: Nonce,
): Capsules {
  const scalar = scalarFromBytes(ephScalarBytes);
  const ck = ContentKey.exposeSecret(contentKey);
  const out = new Uint8Array(memberPubkeys.length * CAPSULE_SIZE);
  for (let i = 0; i < memberPubkeys.length; i++) {
    const shared = ecdhSharedSecret(scalar, memberPubkeys[i]!);
    const tag = deriveViewTagByte(shared);
    const kek = deriveKeyWrap(shared, nonce);
    out[i * CAPSULE_SIZE] = tag;
    for (let j = 0; j < 32; j++) {
      out[i * CAPSULE_SIZE + 1 + j] = ck[j]! ^ kek[j]!;
    }
  }
  return Capsules.fromBytes(out);
}

function scanCapsules(
  data: Uint8Array,
  ephPubkey: EphPubkey,
  myScalar: ViewScalar,
  nonce: Nonce,
): { index: number; contentKey: ContentKey } | null {
  const shared = ecdhSharedSecret(viewScalarToBigInt(myScalar), ephPubkey);
  const myTag = deriveViewTagByte(shared);
  const kek = deriveKeyWrap(shared, nonce);
  let offset = 0;
  let idx = 0;
  while (offset + CAPSULE_SIZE <= data.length) {
    if (data[offset] === myTag) {
      const out = new Uint8Array(32);
      for (let j = 0; j < 32; j++) out[j] = data[offset + 1 + j]! ^ kek[j]!;
      return { index: idx, contentKey: ContentKey.fromBytes(out) };
    }
    offset += CAPSULE_SIZE;
    idx++;
  }
  return null;
}

export function encryptForGroup(
  plaintext: Plaintext,
  memberPubkeys: Pubkey[],
  nonce: Nonce,
  senderSeed: Seed,
): { ephPubkey: EphPubkey; capsules: Capsules; ciphertext: Ciphertext } {
  const ephBytes = deriveGroupEphemeralBytes(senderSeed, nonce);
  const ephScalar = scalarFromBytes(ephBytes);
  const ephPubkey = EphPubkey.fromBytes(RistrettoPoint.BASE.multiply(ephScalar).toRawBytes());
  const ckRaw = crypto.getRandomValues(new Uint8Array(32));
  const contentKey = ContentKey.fromBytes(ckRaw);
  const capsules = buildCapsules(contentKey, memberPubkeys, ephBytes, nonce);
  const cipher = chacha20poly1305(ckRaw, Nonce.chachaBytes(nonce));
  const ct = cipher.encrypt(Plaintext.asBytes(plaintext));
  return { ephPubkey, capsules, ciphertext: Ciphertext.fromBytes(ct) };
}

export function decryptFromGroup(
  content: Uint8Array,
  myScalar: ViewScalar,
  nonce: Nonce,
  knownN?: number,
): Plaintext {
  if (content.length < 32) throw new SampError("insufficient data");
  const ephPubkey = EphPubkey.fromBytes(content.slice(0, 32));
  const afterEph = content.slice(32);
  const scan = scanCapsules(afterEph, ephPubkey, myScalar, nonce);
  if (scan === null) throw new SampError("decryption failed");
  const ckRaw = ContentKey.exposeSecret(scan.contentKey);
  const cipher = chacha20poly1305(ckRaw, Nonce.chachaBytes(nonce));
  if (knownN !== undefined) {
    const ctStart = knownN * CAPSULE_SIZE;
    if (ctStart > afterEph.length) throw new SampError("insufficient data");
    try {
      return Plaintext.fromBytes(cipher.decrypt(afterEph.slice(ctStart)));
    } catch {
      throw new SampError("decryption failed");
    }
  }
  const minN = scan.index + 1;
  const maxN = Math.floor((afterEph.length - 16) / CAPSULE_SIZE);
  for (let n = minN; n <= maxN; n++) {
    const ctStart = n * CAPSULE_SIZE;
    if (ctStart >= afterEph.length) break;
    const c = chacha20poly1305(ckRaw, Nonce.chachaBytes(nonce));
    try {
      return Plaintext.fromBytes(c.decrypt(afterEph.slice(ctStart)));
    } catch {
      continue;
    }
  }
  throw new SampError("decryption failed");
}
