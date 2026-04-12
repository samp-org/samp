import { describe, it, expect } from "vitest";
import {
  ChannelDescription,
  ChannelName,
  ContentType,
  RemarkBytes,
  SampError,
  decodeRemark,
  decodeThreadContent,
  encodeChannelCreate,
  isSampRemark,
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
