import { describe, it, expect } from "vitest";
import {
  ChannelDescription,
  ChannelName,
  SampError,
  Seed,
} from "../src/index.js";

describe("Seed", () => {
  it("toString is redacted", () => {
    const seed = Seed.fromBytes(new Uint8Array(32));
    expect(seed.toString()).toContain("REDACTED");
  });

  it("wrong length throws SampError", () => {
    expect(() => Seed.fromBytes(new Uint8Array(5))).toThrow(SampError);
  });
});

describe("ChannelName", () => {
  it("rejects too-long name", () => {
    expect(() => ChannelName.parse("x".repeat(33))).toThrow(SampError);
  });

  it("accepts valid name", () => {
    const name = ChannelName.parse("test");
    expect(name.asString()).toBe("test");
  });
});

describe("ChannelDescription", () => {
  it("rejects too-long description", () => {
    expect(() => ChannelDescription.parse("x".repeat(129))).toThrow(SampError);
  });
});
