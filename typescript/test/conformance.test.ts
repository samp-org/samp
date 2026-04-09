import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect } from "vitest";
import {
  BlockRef,
  Capsules,
  ChannelDescription,
  ChannelName,
  Ciphertext,
  ContentType,
  EphPubkey,
  Nonce,
  Plaintext,
  Pubkey,
  RemarkBytes,
  SampError,
  Seed,
  ViewScalar,
  ViewTag,
  computeViewTag,
  decodeRemark,
  decodeThreadContent,
  decryptAsSender,
  decrypt,
  decryptFromGroup,
  encodeChannelCreate,
  encodeChannelMsg,
  encodeEncrypted,
  encodeGroup,
  encodeGroupMembers,
  encodePublic,
  encodeThreadContent,
  encrypt,
  encryptForGroup,
  decodeGroupMembers,
  publicFromSeed,
  sr25519SigningScalar,
} from "../src/index.js";

const vectors = JSON.parse(
  readFileSync(resolve(__dirname, "../../e2e/test-vectors.json"), "utf-8"),
);

function h(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s.replace(/^0x/, ""), "hex"));
}

function pk(s: string): Pubkey {
  return Pubkey.fromBytes(h(s));
}

function seed(s: string): Seed {
  return Seed.fromBytes(h(s));
}

function nonce(s: string): Nonce {
  return Nonce.fromBytes(h(s));
}

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function scalarToBytes(v: ViewScalar): Uint8Array {
  const buf = new Uint8Array(32);
  let n = ViewScalar.get(v);
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return buf;
}

describe("keypair", () => {
  it("alice scalar", () => {
    const scalar = sr25519SigningScalar(seed(vectors.alice.seed));
    expect(toHex(scalarToBytes(scalar))).toBe(vectors.alice.signing_scalar.replace("0x", ""));
  });

  it("alice pubkey", () => {
    const pub = publicFromSeed(seed(vectors.alice.seed));
    expect(toHex(pub)).toBe(vectors.alice.sr25519_public.replace("0x", ""));
  });

  it("bob scalar", () => {
    const scalar = sr25519SigningScalar(seed(vectors.bob.seed));
    expect(toHex(scalarToBytes(scalar))).toBe(vectors.bob.signing_scalar.replace("0x", ""));
  });

  it("bob pubkey", () => {
    const pub = publicFromSeed(seed(vectors.bob.seed));
    expect(toHex(pub)).toBe(vectors.bob.sr25519_public.replace("0x", ""));
  });
});

describe("public message", () => {
  it("encode", () => {
    const body = new TextDecoder().decode(h(vectors.public_message.body));
    const remark = encodePublic(pk(vectors.bob.sr25519_public), body);
    expect(toHex(remark)).toBe(vectors.public_message.remark.replace("0x", ""));
  });

  it("decode", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.public_message.remark)));
    expect(r.type).toBe(ContentType.Public);
    if (r.type !== ContentType.Public) throw new Error();
    expect(toHex(new TextEncoder().encode(r.body))).toBe(vectors.public_message.body.replace("0x", ""));
  });
});

describe("encrypted message", () => {
  it("encode", () => {
    const content = encrypt(
      Plaintext.fromBytes(h(vectors.encrypted_message.plaintext)),
      pk(vectors.bob.sr25519_public),
      nonce(vectors.encrypted_message.nonce),
      seed(vectors.alice.seed),
    );
    expect(toHex(content)).toBe(vectors.encrypted_message.encrypted_content.replace("0x", ""));
  });

  it("view tag", () => {
    const vt = computeViewTag(
      seed(vectors.alice.seed),
      pk(vectors.bob.sr25519_public),
      nonce(vectors.encrypted_message.nonce),
    );
    expect(ViewTag.get(vt)).toBe(vectors.encrypted_message.view_tag);
  });

  it("remark", () => {
    const content = Ciphertext.fromBytes(h(vectors.encrypted_message.encrypted_content));
    const remark = encodeEncrypted(
      ContentType.Encrypted,
      ViewTag.from(vectors.encrypted_message.view_tag),
      nonce(vectors.encrypted_message.nonce),
      content,
    );
    expect(toHex(remark)).toBe(vectors.encrypted_message.remark.replace("0x", ""));
  });

  it("intermediates", () => {
    const content = h(vectors.encrypted_message.encrypted_content);
    expect(toHex(content.slice(0, 32))).toBe(vectors.encrypted_message.ephemeral_pubkey.replace("0x", ""));
    expect(toHex(content.slice(32, 64))).toBe(vectors.encrypted_message.sealed_to.replace("0x", ""));
    expect(toHex(content.slice(64))).toBe(vectors.encrypted_message.ciphertext_with_tag.replace("0x", ""));
  });

  it("recipient decrypt", () => {
    const bobScalar = sr25519SigningScalar(seed(vectors.bob.seed));
    const parsed = decodeRemark(RemarkBytes.fromBytes(h(vectors.encrypted_message.remark)));
    if (parsed.type !== ContentType.Encrypted) throw new Error();
    const plaintext = decrypt(parsed.ciphertext, parsed.nonce, bobScalar);
    expect(toHex(plaintext)).toBe(vectors.encrypted_message.plaintext.replace("0x", ""));
  });
});

describe("sender self-decryption", () => {
  it("decrypt", () => {
    const parsed = decodeRemark(RemarkBytes.fromBytes(h(vectors.encrypted_message.remark)));
    if (parsed.type !== ContentType.Encrypted) throw new Error();
    const plaintext = decryptAsSender(parsed.ciphertext, parsed.nonce, seed(vectors.alice.seed));
    expect(toHex(plaintext)).toBe(vectors.sender_self_decryption.plaintext.replace("0x", ""));
  });

  it("unsealed recipient is bob", () => {
    expect(vectors.sender_self_decryption.unsealed_recipient).toBe(vectors.bob.sr25519_public);
  });
});

describe("thread message", () => {
  it("encode + encrypt + decrypt", () => {
    const th = vectors.thread_message.thread_ref;
    const rt = vectors.thread_message.reply_to;
    const ct = vectors.thread_message.continues;

    const threadPlaintext = encodeThreadContent(
      BlockRef.fromParts(th[0], th[1]),
      BlockRef.fromParts(rt[0], rt[1]),
      BlockRef.fromParts(ct[0], ct[1]),
      h(vectors.thread_message.body),
    );
    expect(toHex(threadPlaintext)).toBe(vectors.thread_message.thread_plaintext.replace("0x", ""));

    const encrypted = encrypt(
      Plaintext.fromBytes(threadPlaintext),
      pk(vectors.bob.sr25519_public),
      nonce(vectors.thread_message.nonce),
      seed(vectors.alice.seed),
    );
    expect(toHex(encrypted)).toBe(vectors.thread_message.encrypted_content.replace("0x", ""));

    const bobScalar = sr25519SigningScalar(seed(vectors.bob.seed));
    const parsed = decodeRemark(RemarkBytes.fromBytes(h(vectors.thread_message.remark)));
    if (parsed.type !== ContentType.Thread) throw new Error();
    const decrypted = decrypt(parsed.ciphertext, parsed.nonce, bobScalar);
    const { thread, replyTo, body } = decodeThreadContent(decrypted);
    expect(thread.block as number).toBe(th[0]);
    expect(replyTo.block as number).toBe(rt[0]);
    expect(toHex(body)).toBe(vectors.thread_message.body.replace("0x", ""));
  });
});

describe("channel message", () => {
  it("encode", () => {
    const ch = vectors.channel_message;
    const remark = encodeChannelMsg(
      BlockRef.fromParts(ch.channel_ref[0], ch.channel_ref[1]),
      BlockRef.fromParts(ch.reply_to[0], ch.reply_to[1]),
      BlockRef.fromParts(ch.continues[0], ch.continues[1]),
      h(ch.body),
    );
    expect(toHex(remark)).toBe(ch.remark.replace("0x", ""));
  });

  it("decode", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.channel_message.remark)));
    expect(r.type).toBe(ContentType.Channel);
  });
});

describe("channel create", () => {
  it("encode", () => {
    const remark = encodeChannelCreate(
      ChannelName.parse(vectors.channel_create.name),
      ChannelDescription.parse(vectors.channel_create.description),
    );
    expect(toHex(remark)).toBe(vectors.channel_create.remark.replace("0x", ""));
  });

  it("decode", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.channel_create.remark)));
    if (r.type !== ContentType.ChannelCreate) throw new Error();
    expect(r.name.asString()).toBe(vectors.channel_create.name);
    expect(r.description.asString()).toBe(vectors.channel_create.description);
  });
});

describe("group message", () => {
  it("remark decode", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.group_message.remark)));
    expect(r.type).toBe(ContentType.Group);
    if (r.type !== ContentType.Group) throw new Error();
    expect(toHex(r.nonce)).toBe(vectors.group_message.nonce.replace("0x", ""));
  });

  it("member list encode/decode", () => {
    const members = (vectors.group_message.members as string[]).map((m) => pk(m));
    const encoded = encodeGroupMembers(members);
    expect(toHex(encoded)).toBe(vectors.group_message.member_list_encoded.replace("0x", ""));
    const { members: decoded, body } = decodeGroupMembers(encoded);
    expect(decoded.length).toBe(3);
    for (let i = 0; i < 3; i++) {
      expect(toHex(decoded[i]!)).toBe(
        (vectors.group_message.members[i] as string).replace("0x", ""),
      );
    }
    expect(body.length).toBe(0);
  });

  it("alice decrypt", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.group_message.remark)));
    if (r.type !== ContentType.Group) throw new Error();
    const aliceScalar = sr25519SigningScalar(seed(vectors.alice.seed));
    const plaintext = decryptFromGroup(r.content, aliceScalar, r.nonce, 3);
    expect(toHex(plaintext)).toBe(vectors.group_message.root_plaintext.replace("0x", ""));
  });

  it("bob decrypt", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.group_message.remark)));
    if (r.type !== ContentType.Group) throw new Error();
    const bobScalar = sr25519SigningScalar(seed(vectors.bob.seed));
    const plaintext = decryptFromGroup(r.content, bobScalar, r.nonce, 3);
    expect(toHex(plaintext)).toBe(vectors.group_message.root_plaintext.replace("0x", ""));
  });

  it("charlie decrypt", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.group_message.remark)));
    if (r.type !== ContentType.Group) throw new Error();
    const charlieScalar = sr25519SigningScalar(seed(vectors.charlie.seed));
    const plaintext = decryptFromGroup(r.content, charlieScalar, r.nonce, 3);
    expect(toHex(plaintext)).toBe(vectors.group_message.root_plaintext.replace("0x", ""));
  });

  it("bob decrypt trial AEAD", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.group_message.remark)));
    if (r.type !== ContentType.Group) throw new Error();
    const bobScalar = sr25519SigningScalar(seed(vectors.bob.seed));
    const plaintext = decryptFromGroup(r.content, bobScalar, r.nonce);
    expect(toHex(plaintext)).toBe(vectors.group_message.root_plaintext.replace("0x", ""));
  });
});

describe("edge cases", () => {
  it("empty body public", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.edge_cases.empty_body_public)));
    expect(r.type).toBe(ContentType.Public);
    if (r.type !== ContentType.Public) throw new Error();
    expect(r.body.length).toBe(0);
  });

  it("min encrypted", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.edge_cases.min_encrypted)));
    expect(r.type).toBe(ContentType.Encrypted);
  });

  it("empty desc channel create", () => {
    const r = decodeRemark(RemarkBytes.fromBytes(h(vectors.edge_cases.empty_desc_channel_create)));
    if (r.type !== ContentType.ChannelCreate) throw new Error();
    expect(r.name.asString()).toBe("test");
    expect(r.description.asString()).toBe("");
  });
});

describe("content type byte values pinned", () => {
  it("enum values match spec", () => {
    expect(ContentType.Public as number).toBe(0x10);
    expect(ContentType.Encrypted as number).toBe(0x11);
    expect(ContentType.Thread as number).toBe(0x12);
    expect(ContentType.ChannelCreate as number).toBe(0x13);
    expect(ContentType.Channel as number).toBe(0x14);
    expect(ContentType.Group as number).toBe(0x15);
  });
});

describe("typed wrappers round-trip", () => {
  it("pubkey/nonce idempotent", () => {
    const bobRaw = h(vectors.bob.sr25519_public);
    expect(toHex(Pubkey.fromBytes(bobRaw))).toBe(toHex(bobRaw));
    const nonceRaw = h(vectors.encrypted_message.nonce);
    expect(toHex(Nonce.fromBytes(nonceRaw))).toBe(toHex(nonceRaw));
  });

  it("rejects wrong-length pubkey", () => {
    expect(() => Pubkey.fromBytes(new Uint8Array(31))).toThrow(SampError);
  });
});

describe("block ref display", () => {
  it("formats as #N.I", () => {
    expect(BlockRef.fromParts(42, 7).toString()).toBe("#42.7");
  });
});

describe("negative cases", () => {
  it("non-SAMP version", () => {
    expect(() => decodeRemark(RemarkBytes.fromBytes(h(vectors.negative_cases.non_samp_version)))).toThrow();
  });

  it("reserved type", () => {
    expect(() => decodeRemark(RemarkBytes.fromBytes(h(vectors.negative_cases.reserved_type)))).toThrow();
  });

  it("truncated encrypted", () => {
    expect(() => decodeRemark(RemarkBytes.fromBytes(h(vectors.negative_cases.truncated_encrypted)))).toThrow();
  });
});

describe("channel create validation", () => {
  it("encode_channel_create_name_too_long_throws", () => {
    expect(() => ChannelName.parse("x".repeat(33))).toThrow(SampError);
  });

  it("encode_channel_create_empty_name_throws", () => {
    expect(() => ChannelName.parse("")).toThrow(SampError);
  });

  it("encode_channel_create_desc_too_long_throws", () => {
    expect(() => ChannelDescription.parse("x".repeat(129))).toThrow(SampError);
  });
});

describe("group encrypt/decrypt", () => {
  const aliceSeed = Seed.fromBytes(new Uint8Array(32).fill(0xaa));
  const bobSeed = Seed.fromBytes(new Uint8Array(32).fill(0xbb));
  const charlieSeed = Seed.fromBytes(new Uint8Array(32).fill(0xcc));

  it("group_regular_message_roundtrip", () => {
    const alicePub = publicFromSeed(aliceSeed);
    const bobPub = publicFromSeed(bobSeed);
    const members = [alicePub, bobPub];
    const n = Nonce.fromBytes(crypto.getRandomValues(new Uint8Array(12)));

    const plaintext = encodeThreadContent(
      BlockRef.fromParts(100, 1),
      BlockRef.zero(),
      BlockRef.zero(),
      new TextEncoder().encode("non-root msg"),
    );

    const { ephPubkey, capsules, ciphertext } = encryptForGroup(
      Plaintext.fromBytes(plaintext),
      members,
      n,
      aliceSeed,
    );
    void ephPubkey;
    void capsules;
    void ciphertext;
    const remark = encodeGroup(n, ephPubkey, capsules, ciphertext);

    const r = decodeRemark(remark);
    expect(r.type).toBe(ContentType.Group);
    if (r.type !== ContentType.Group) throw new Error();

    const bobScalar = sr25519SigningScalar(bobSeed);
    const decrypted = decryptFromGroup(r.content, bobScalar, r.nonce, 2);
    const { thread, body } = decodeThreadContent(decrypted);
    expect(thread.block as number).toBe(100);
    expect(thread.index as number).toBe(1);
    expect(new TextDecoder().decode(body)).toBe("non-root msg");
  });

  it("group_non_member_rejected", () => {
    const alicePub = publicFromSeed(aliceSeed);
    const bobPub = publicFromSeed(bobSeed);
    const members = [alicePub, bobPub];
    const n = Nonce.fromBytes(crypto.getRandomValues(new Uint8Array(12)));

    const plaintext = encodeThreadContent(
      BlockRef.fromParts(100, 1),
      BlockRef.zero(),
      BlockRef.zero(),
      new TextEncoder().encode("secret"),
    );

    const { ephPubkey, capsules, ciphertext } = encryptForGroup(
      Plaintext.fromBytes(plaintext),
      members,
      n,
      aliceSeed,
    );
    const remark = encodeGroup(n, ephPubkey, capsules, ciphertext);
    const r = decodeRemark(remark);
    if (r.type !== ContentType.Group) throw new Error();

    const charlieScalar = sr25519SigningScalar(charlieSeed);
    expect(() => decryptFromGroup(r.content, charlieScalar, r.nonce, 2)).toThrow();
  });
});

// Keep type-only references so unused-import warnings don't fire
void Capsules;
void EphPubkey;
