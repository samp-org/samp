import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect } from "vitest";
import {
  encodePublic,
  encodeEncrypted,
  encodeChannelMsg,
  encodeChannelCreate,
  decodeRemark,
  encodeThreadContent,
  decodeThreadContent,
  decodeChannelCreate,
  encodeGroupMembers,
  decodeGroupMembers,
  encodeGroup,
  encryptForGroup,
  CONTENT_TYPE_PUBLIC,
  CONTENT_TYPE_ENCRYPTED,
  CONTENT_TYPE_CHANNEL,
  CONTENT_TYPE_GROUP,
  sr25519SigningScalar,
  publicFromSeed,
  encrypt,
  decrypt,
  decryptAsSender,
  computeViewTag,
  decryptFromGroup,
  SampError,
} from "../src/index.js";
import { bytesToNumberLE } from "@noble/curves/abstract/utils";

const vectors = JSON.parse(
  readFileSync(resolve(__dirname, "../../e2e/test-vectors.json"), "utf-8"),
);

function h(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s.replace(/^0x/, ""), "hex"));
}

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function scalarToBytes(s: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let v = s;
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

// --- Keypair derivation ---

describe("keypair", () => {
  it("alice scalar", () => {
    const scalar = sr25519SigningScalar(h(vectors.alice.seed));
    expect(toHex(scalarToBytes(scalar))).toBe(vectors.alice.signing_scalar.replace("0x", ""));
  });

  it("alice pubkey", () => {
    const pub = publicFromSeed(h(vectors.alice.seed));
    expect(toHex(pub)).toBe(vectors.alice.sr25519_public.replace("0x", ""));
  });

  it("bob scalar", () => {
    const scalar = sr25519SigningScalar(h(vectors.bob.seed));
    expect(toHex(scalarToBytes(scalar))).toBe(vectors.bob.signing_scalar.replace("0x", ""));
  });

  it("bob pubkey", () => {
    const pub = publicFromSeed(h(vectors.bob.seed));
    expect(toHex(pub)).toBe(vectors.bob.sr25519_public.replace("0x", ""));
  });
});

// --- Public message ---

describe("public message", () => {
  it("encode", () => {
    const remark = encodePublic(h(vectors.bob.sr25519_public), h(vectors.public_message.body));
    expect(toHex(remark)).toBe(vectors.public_message.remark.replace("0x", ""));
  });

  it("decode", () => {
    const r = decodeRemark(h(vectors.public_message.remark));
    expect(r.contentType).toBe(CONTENT_TYPE_PUBLIC);
    expect(toHex(r.content)).toBe(vectors.public_message.body.replace("0x", ""));
  });
});

// --- Encrypted message ---

describe("encrypted message", () => {
  it("encode", () => {
    const content = encrypt(
      h(vectors.encrypted_message.plaintext),
      h(vectors.bob.sr25519_public),
      h(vectors.encrypted_message.nonce),
      h(vectors.alice.seed),
    );
    expect(toHex(content)).toBe(vectors.encrypted_message.encrypted_content.replace("0x", ""));
  });

  it("view tag", () => {
    const vt = computeViewTag(
      h(vectors.alice.seed),
      h(vectors.bob.sr25519_public),
      h(vectors.encrypted_message.nonce),
    );
    expect(vt).toBe(vectors.encrypted_message.view_tag);
  });

  it("remark", () => {
    const content = h(vectors.encrypted_message.encrypted_content);
    const remark = encodeEncrypted(CONTENT_TYPE_ENCRYPTED, vectors.encrypted_message.view_tag, h(vectors.encrypted_message.nonce), content);
    expect(toHex(remark)).toBe(vectors.encrypted_message.remark.replace("0x", ""));
  });

  it("intermediates", () => {
    const content = h(vectors.encrypted_message.encrypted_content);
    expect(toHex(content.slice(0, 32))).toBe(vectors.encrypted_message.ephemeral_pubkey.replace("0x", ""));
    expect(toHex(content.slice(32, 64))).toBe(vectors.encrypted_message.sealed_to.replace("0x", ""));
    expect(toHex(content.slice(64))).toBe(vectors.encrypted_message.ciphertext_with_tag.replace("0x", ""));
  });

  it("recipient decrypt", () => {
    const bobScalar = sr25519SigningScalar(h(vectors.bob.seed));
    const plaintext = decrypt(
      h(vectors.encrypted_message.encrypted_content),
      bobScalar,
      h(vectors.encrypted_message.nonce),
    );
    expect(toHex(plaintext)).toBe(vectors.encrypted_message.plaintext.replace("0x", ""));
  });
});

// --- Sender self-decryption ---

describe("sender self-decryption", () => {
  it("decrypt", () => {
    const plaintext = decryptAsSender(
      h(vectors.encrypted_message.encrypted_content),
      h(vectors.alice.seed),
      h(vectors.encrypted_message.nonce),
    );
    expect(toHex(plaintext)).toBe(vectors.sender_self_decryption.plaintext.replace("0x", ""));
  });

  it("unsealed recipient is bob", () => {
    expect(vectors.sender_self_decryption.unsealed_recipient).toBe(vectors.bob.sr25519_public);
  });
});

// --- Thread message ---

describe("thread message", () => {
  it("encode + encrypt + decrypt", () => {
    const th = vectors.thread_message.thread_ref;
    const rt = vectors.thread_message.reply_to;
    const ct = vectors.thread_message.continues;

    const threadPlaintext = encodeThreadContent(
      { block: th[0], index: th[1] },
      { block: rt[0], index: rt[1] },
      { block: ct[0], index: ct[1] },
      h(vectors.thread_message.body),
    );
    expect(toHex(threadPlaintext)).toBe(vectors.thread_message.thread_plaintext.replace("0x", ""));

    const encrypted = encrypt(
      threadPlaintext,
      h(vectors.bob.sr25519_public),
      h(vectors.thread_message.nonce),
      h(vectors.alice.seed),
    );
    expect(toHex(encrypted)).toBe(vectors.thread_message.encrypted_content.replace("0x", ""));

    const bobScalar = sr25519SigningScalar(h(vectors.bob.seed));
    const decrypted = decrypt(encrypted, bobScalar, h(vectors.thread_message.nonce));
    const { thread, replyTo, body } = decodeThreadContent(decrypted);
    expect(thread.block).toBe(th[0]);
    expect(replyTo.block).toBe(rt[0]);
    expect(toHex(body)).toBe(vectors.thread_message.body.replace("0x", ""));
  });
});

// --- Channel message ---

describe("channel message", () => {
  it("encode", () => {
    const ch = vectors.channel_message;
    const remark = encodeChannelMsg(
      { block: ch.channel_ref[0], index: ch.channel_ref[1] },
      { block: ch.reply_to[0], index: ch.reply_to[1] },
      { block: ch.continues[0], index: ch.continues[1] },
      h(ch.body),
    );
    expect(toHex(remark)).toBe(ch.remark.replace("0x", ""));
  });

  it("decode", () => {
    const r = decodeRemark(h(vectors.channel_message.remark));
    expect(r.contentType).toBe(CONTENT_TYPE_CHANNEL);
  });
});

// --- Channel creation ---

describe("channel create", () => {
  it("encode", () => {
    const remark = encodeChannelCreate(vectors.channel_create.name, vectors.channel_create.description);
    expect(toHex(remark)).toBe(vectors.channel_create.remark.replace("0x", ""));
  });

  it("decode", () => {
    const r = decodeRemark(h(vectors.channel_create.remark));
    const { name, description } = decodeChannelCreate(r.content);
    expect(name).toBe(vectors.channel_create.name);
    expect(description).toBe(vectors.channel_create.description);
  });
});

// --- Group message ---

describe("group message", () => {
  it("remark decode", () => {
    const r = decodeRemark(h(vectors.group_message.remark));
    expect(r.contentType).toBe(CONTENT_TYPE_GROUP);
    expect(toHex(r.nonce)).toBe(vectors.group_message.nonce.replace("0x", ""));
  });

  it("member list encode/decode", () => {
    const members = vectors.group_message.members.map((m: string) => h(m));
    const encoded = encodeGroupMembers(members);
    expect(toHex(encoded)).toBe(vectors.group_message.member_list_encoded.replace("0x", ""));
    const { members: decoded, body } = decodeGroupMembers(encoded);
    expect(decoded.length).toBe(3);
    for (let i = 0; i < 3; i++) {
      expect(toHex(decoded[i])).toBe(vectors.group_message.members[i].replace("0x", ""));
    }
    expect(body.length).toBe(0);
  });

  it("alice decrypt", () => {
    const r = decodeRemark(h(vectors.group_message.remark));
    const aliceScalar = sr25519SigningScalar(h(vectors.alice.seed));
    const plaintext = decryptFromGroup(r.content, aliceScalar, r.nonce, 3);
    expect(toHex(plaintext)).toBe(vectors.group_message.root_plaintext.replace("0x", ""));
  });

  it("bob decrypt", () => {
    const r = decodeRemark(h(vectors.group_message.remark));
    const bobScalar = sr25519SigningScalar(h(vectors.bob.seed));
    const plaintext = decryptFromGroup(r.content, bobScalar, r.nonce, 3);
    expect(toHex(plaintext)).toBe(vectors.group_message.root_plaintext.replace("0x", ""));
  });

  it("charlie decrypt", () => {
    const r = decodeRemark(h(vectors.group_message.remark));
    const charlieScalar = sr25519SigningScalar(h(vectors.charlie.seed));
    const plaintext = decryptFromGroup(r.content, charlieScalar, r.nonce, 3);
    expect(toHex(plaintext)).toBe(vectors.group_message.root_plaintext.replace("0x", ""));
  });

  it("bob decrypt trial AEAD", () => {
    const r = decodeRemark(h(vectors.group_message.remark));
    const bobScalar = sr25519SigningScalar(h(vectors.bob.seed));
    const plaintext = decryptFromGroup(r.content, bobScalar, r.nonce);
    expect(toHex(plaintext)).toBe(vectors.group_message.root_plaintext.replace("0x", ""));
  });
});

// --- Edge cases ---

describe("edge cases", () => {
  it("empty body public", () => {
    const r = decodeRemark(h(vectors.edge_cases.empty_body_public));
    expect(r.contentType).toBe(CONTENT_TYPE_PUBLIC);
    expect(r.content.length).toBe(0);
  });

  it("min encrypted", () => {
    const r = decodeRemark(h(vectors.edge_cases.min_encrypted));
    expect(r.contentType).toBe(CONTENT_TYPE_ENCRYPTED);
  });

  it("empty desc channel create", () => {
    const r = decodeRemark(h(vectors.edge_cases.empty_desc_channel_create));
    const { name, description } = decodeChannelCreate(r.content);
    expect(name).toBe("test");
    expect(description).toBe("");
  });
});

// --- Negative cases ---

describe("negative cases", () => {
  it("non-SAMP version", () => {
    expect(() => decodeRemark(h(vectors.negative_cases.non_samp_version))).toThrow();
  });

  it("reserved type", () => {
    expect(() => decodeRemark(h(vectors.negative_cases.reserved_type))).toThrow();
  });

  it("truncated encrypted", () => {
    expect(() => decodeRemark(h(vectors.negative_cases.truncated_encrypted))).toThrow();
  });
});

// --- Channel create validation ---

describe("channel create validation", () => {
  it("encode_channel_create_name_too_long_throws", () => {
    expect(() => encodeChannelCreate("x".repeat(33), "desc")).toThrow(SampError);
  });

  it("encode_channel_create_empty_name_throws", () => {
    expect(() => encodeChannelCreate("", "desc")).toThrow(SampError);
  });

  it("encode_channel_create_desc_too_long_throws", () => {
    expect(() => encodeChannelCreate("valid", "x".repeat(129))).toThrow(SampError);
  });
});

// --- Group encrypt/decrypt ---

describe("group encrypt/decrypt", () => {
  const aliceSeed = new Uint8Array(32).fill(0xaa);
  const bobSeed = new Uint8Array(32).fill(0xbb);
  const charlieSeed = new Uint8Array(32).fill(0xcc);

  it("group_regular_message_roundtrip", () => {
    const alicePub = publicFromSeed(aliceSeed);
    const bobPub = publicFromSeed(bobSeed);
    const members = [alicePub, bobPub];
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const plaintext = encodeThreadContent(
      { block: 100, index: 1 },
      { block: 0, index: 0 },
      { block: 0, index: 0 },
      new TextEncoder().encode("non-root msg"),
    );

    const { ephPubkey, capsules, ciphertext } = encryptForGroup(plaintext, members, nonce, aliceSeed);
    const remark = encodeGroup(nonce, ephPubkey, capsules, ciphertext);

    const r = decodeRemark(remark);
    expect(r.contentType).toBe(CONTENT_TYPE_GROUP);

    const bobScalar = sr25519SigningScalar(bobSeed);
    const decrypted = decryptFromGroup(r.content, bobScalar, r.nonce, 2);
    const { thread, body } = decodeThreadContent(decrypted);
    expect(thread.block).toBe(100);
    expect(thread.index).toBe(1);
    expect(new TextDecoder().decode(body)).toBe("non-root msg");
  });

  it("group_non_member_rejected", () => {
    const alicePub = publicFromSeed(aliceSeed);
    const bobPub = publicFromSeed(bobSeed);
    const members = [alicePub, bobPub];
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const plaintext = encodeThreadContent(
      { block: 100, index: 1 },
      { block: 0, index: 0 },
      { block: 0, index: 0 },
      new TextEncoder().encode("secret"),
    );

    const { ephPubkey, capsules, ciphertext } = encryptForGroup(plaintext, members, nonce, aliceSeed);
    const remark = encodeGroup(nonce, ephPubkey, capsules, ciphertext);
    const r = decodeRemark(remark);

    const charlieScalar = sr25519SigningScalar(charlieSeed);
    expect(() => decryptFromGroup(r.content, charlieScalar, r.nonce, 2)).toThrow();
  });
});
