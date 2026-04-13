import { describe, it, expect } from "vitest";
import {
  BlockRef,
  ChannelDescription,
  ChannelName,
  ContentType,
  Nonce,
  Plaintext,
  Pubkey,
  RemarkBytes,
  SampError,
  Seed,
  ViewTag,
  contentTypeFromByte,
  decodeChannelContent,
  decodeGroupContent,
  decodeGroupMembers,
  decodeRemark,
  decodeThreadContent,
  encodeChannelContent,
  encodeChannelCreate,
  encodeChannelMsg,
  encodeEncrypted,
  encodeGroupMembers,
  encrypt,
  isSampRemark,
  publicFromSeed,
} from "../src/index.js";

describe("decodeRemark", () => {
  it("rejects empty bytes", () => {
    expect(() => decodeRemark(RemarkBytes.fromBytes(new Uint8Array(0)))).toThrow(SampError);
  });
});

describe("isSampRemark", () => {
  it("returns false for non-SAMP prefix", () => {
    expect(isSampRemark(new Uint8Array([0x20, 0x00]))).toBe(false);
  });
});

describe("channel create round trip", () => {
  it("encodes and decodes name/description", () => {
    const name = ChannelName.parse("general");
    const desc = ChannelDescription.parse("A test channel");
    const encoded = encodeChannelCreate(name, desc);
    const decoded = decodeRemark(encoded);
    expect(decoded.type).toBe(ContentType.ChannelCreate);
    if (decoded.type === ContentType.ChannelCreate) {
      expect(decoded.name.asString()).toBe("general");
      expect(decoded.description.asString()).toBe("A test channel");
    }
  });
});

describe("decodeThreadContent", () => {
  it("rejects truncated data", () => {
    expect(() => decodeThreadContent(new Uint8Array(5))).toThrow(SampError);
  });
});

describe("encodeEncrypted round trip", () => {
  it("encodes and decodes through decodeRemark", () => {
    const senderSeed = Seed.fromBytes(new Uint8Array(32).fill(0xaa));
    const recipientPub = publicFromSeed(Seed.fromBytes(new Uint8Array(32).fill(0xbb)));
    const nonce = Nonce.fromBytes(new Uint8Array(12).fill(0x01));
    const pt = Plaintext.fromBytes(new TextEncoder().encode("round trip test"));
    const ct = encrypt(pt, recipientPub, nonce, senderSeed);

    const encoded = encodeEncrypted(ContentType.Encrypted, ViewTag.from(0), nonce, ct);
    const decoded = decodeRemark(encoded);
    expect(decoded.type).toBe(ContentType.Encrypted);
    if (decoded.type === ContentType.Encrypted) {
      expect(Buffer.from(decoded.nonce)).toEqual(Buffer.from(nonce));
      expect(Buffer.from(decoded.ciphertext)).toEqual(Buffer.from(ct));
    }
  });
});

describe("encodeGroupMembers + decodeGroupMembers round trip", () => {
  it("round-trips 2 pubkeys", () => {
    const pk1 = Pubkey.fromBytes(new Uint8Array(32).fill(0x01));
    const pk2 = Pubkey.fromBytes(new Uint8Array(32).fill(0x02));
    const encoded = encodeGroupMembers([pk1, pk2]);
    const { members, body } = decodeGroupMembers(encoded);
    expect(members.length).toBe(2);
    expect(Buffer.from(members[0]!)).toEqual(Buffer.from(pk1));
    expect(Buffer.from(members[1]!)).toEqual(Buffer.from(pk2));
    expect(body.length).toBe(0);
  });
});

describe("contentTypeFromByte", () => {
  it("all known types", () => {
    expect(contentTypeFromByte(0x10)).toBe(ContentType.Public);
    expect(contentTypeFromByte(0x11)).toBe(ContentType.Encrypted);
    expect(contentTypeFromByte(0x12)).toBe(ContentType.Thread);
    expect(contentTypeFromByte(0x13)).toBe(ContentType.ChannelCreate);
    expect(contentTypeFromByte(0x14)).toBe(ContentType.Channel);
    expect(contentTypeFromByte(0x15)).toBe(ContentType.Group);
  });

  it("reserved 0x16 throws", () => {
    expect(() => contentTypeFromByte(0x16)).toThrow(SampError);
  });

  it("reserved 0x17 throws", () => {
    expect(() => contentTypeFromByte(0x17)).toThrow(SampError);
  });

  it("application type >= 0x18", () => {
    expect(contentTypeFromByte(0x18)).toBe(ContentType.Application);
    expect(contentTypeFromByte(0x1f)).toBe(ContentType.Application);
  });

  it("wrong version throws", () => {
    expect(() => contentTypeFromByte(0x20)).toThrow(SampError);
  });
});

describe("decodeRemark channel message", () => {
  it("decodes a channel message", () => {
    const remark = encodeChannelMsg(
      BlockRef.fromParts(100, 1),
      BlockRef.fromParts(50, 2),
      BlockRef.zero(),
      "hello channel",
    );
    const r = decodeRemark(remark);
    expect(r.type).toBe(ContentType.Channel);
    if (r.type === ContentType.Channel) {
      expect(r.channelRef.block as number).toBe(100);
      expect(r.channelRef.index as number).toBe(1);
      expect(r.replyTo.block as number).toBe(50);
      expect(r.body).toBe("hello channel");
    }
  });

  it("rejects truncated channel message", () => {
    const buf = new Uint8Array(18);
    buf[0] = ContentType.Channel;
    expect(() => decodeRemark(RemarkBytes.fromBytes(buf))).toThrow(SampError);
  });
});

describe("decodeRemark group", () => {
  it("decodes a group envelope", () => {
    const buf = new Uint8Array(20);
    buf[0] = ContentType.Group;
    buf.set(new Uint8Array(12).fill(0x42), 1);
    buf.set(new Uint8Array(7).fill(0xab), 13);
    const r = decodeRemark(RemarkBytes.fromBytes(buf));
    expect(r.type).toBe(ContentType.Group);
    if (r.type === ContentType.Group) {
      expect(Buffer.from(r.nonce)).toEqual(Buffer.from(new Uint8Array(12).fill(0x42)));
      expect(r.content.length).toBe(7);
    }
  });

  it("rejects truncated group", () => {
    const buf = new Uint8Array(12);
    buf[0] = ContentType.Group;
    expect(() => decodeRemark(RemarkBytes.fromBytes(buf))).toThrow(SampError);
  });
});

describe("decodeRemark application type", () => {
  it("decodes application type >= 0x18", () => {
    const buf = new Uint8Array([0x18, 0xde, 0xad]);
    const r = decodeRemark(RemarkBytes.fromBytes(buf));
    expect(r.type).toBe(ContentType.Application);
    if (r.type === ContentType.Application) {
      expect(r.tag).toBe(0x18);
      expect(r.payload.length).toBe(2);
    }
  });

  it("decodes application type 0x1f", () => {
    const buf = new Uint8Array([0x1f, 0x01]);
    const r = decodeRemark(RemarkBytes.fromBytes(buf));
    expect(r.type).toBe(ContentType.Application);
    if (r.type === ContentType.Application) {
      expect(r.tag).toBe(0x1f);
    }
  });
});

describe("decodeRemark reserved types", () => {
  it("0x16 throws", () => {
    expect(() => decodeRemark(RemarkBytes.fromBytes(new Uint8Array([0x16])))).toThrow(SampError);
  });

  it("0x17 throws", () => {
    expect(() => decodeRemark(RemarkBytes.fromBytes(new Uint8Array([0x17])))).toThrow(SampError);
  });
});

describe("decodeChannelContent", () => {
  it("round trips through encode/decode", () => {
    const replyTo = BlockRef.fromParts(10, 2);
    const continues = BlockRef.zero();
    const body = new TextEncoder().encode("channel body");
    const encoded = encodeChannelContent(replyTo, continues, body);
    const decoded = decodeChannelContent(encoded);
    expect(decoded.replyTo.block as number).toBe(10);
    expect(decoded.replyTo.index as number).toBe(2);
    expect(decoded.continues.isZero()).toBe(true);
    expect(new TextDecoder().decode(decoded.body)).toBe("channel body");
  });

  it("rejects truncated data", () => {
    expect(() => decodeChannelContent(new Uint8Array(5))).toThrow(SampError);
  });
});

describe("decodeGroupContent", () => {
  it("decodes valid group content", () => {
    const buf = new Uint8Array(22);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 200, true);
    dv.setUint16(4, 3, true);
    dv.setUint32(6, 0, true);
    dv.setUint16(10, 0, true);
    dv.setUint32(12, 0, true);
    dv.setUint16(16, 0, true);
    buf[18] = 0xaa;
    buf[19] = 0xbb;
    buf[20] = 0xcc;
    buf[21] = 0xdd;
    const decoded = decodeGroupContent(buf);
    expect(decoded.groupRef.block as number).toBe(200);
    expect(decoded.groupRef.index as number).toBe(3);
    expect(decoded.body.length).toBe(4);
  });

  it("rejects truncated data", () => {
    expect(() => decodeGroupContent(new Uint8Array(10))).toThrow(SampError);
  });
});

describe("decodeGroupMembers edge cases", () => {
  it("rejects empty input", () => {
    expect(() => decodeGroupMembers(new Uint8Array(0))).toThrow(SampError);
  });

  it("rejects truncated member data", () => {
    const buf = new Uint8Array([2, ...new Uint8Array(33)]);
    expect(() => decodeGroupMembers(buf)).toThrow(SampError);
  });

  it("zero members", () => {
    const { members, body } = decodeGroupMembers(new Uint8Array([0, 0xff]));
    expect(members.length).toBe(0);
    expect(body.length).toBe(1);
  });
});

describe("decodeChannelCreatePayload edge cases", () => {
  it("rejects zero-length name", () => {
    const buf = new Uint8Array([ContentType.ChannelCreate, 0x00, 0x00]);
    expect(() => decodeRemark(RemarkBytes.fromBytes(buf))).toThrow(SampError);
  });

  it("rejects name > 32 bytes", () => {
    const buf = new Uint8Array(3 + 33 + 1);
    buf[0] = ContentType.ChannelCreate;
    buf[1] = 33;
    buf.fill(0x61, 2, 2 + 33);
    buf[2 + 33] = 0;
    expect(() => decodeRemark(RemarkBytes.fromBytes(buf))).toThrow(SampError);
  });

  it("rejects desc > 128 bytes", () => {
    const nb = new TextEncoder().encode("test");
    const buf = new Uint8Array(3 + nb.length + 129);
    buf[0] = ContentType.ChannelCreate;
    buf[1] = nb.length;
    buf.set(nb, 2);
    buf[2 + nb.length] = 129;
    buf.fill(0x61, 3 + nb.length, 3 + nb.length + 129);
    expect(() => decodeRemark(RemarkBytes.fromBytes(buf))).toThrow(SampError);
  });

  it("rejects truncated channel create (too short for name)", () => {
    const buf = new Uint8Array([ContentType.ChannelCreate]);
    expect(() => decodeRemark(RemarkBytes.fromBytes(buf))).toThrow(SampError);
  });

  it("rejects truncated channel create (name len ok, data missing)", () => {
    const buf = new Uint8Array([ContentType.ChannelCreate, 5, 0x61]);
    expect(() => decodeRemark(RemarkBytes.fromBytes(buf))).toThrow(SampError);
  });

  it("rejects truncated channel create (desc data missing)", () => {
    const buf = new Uint8Array([ContentType.ChannelCreate, 1, 0x61, 5]);
    expect(() => decodeRemark(RemarkBytes.fromBytes(buf))).toThrow(SampError);
  });
});
