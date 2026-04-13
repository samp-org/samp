import { describe, it, expect } from "vitest";
import { Seed, sr25519Sign } from "../src/index.js";
import { waitReady } from "@polkadot/wasm-crypto";

describe("sr25519Sign", () => {
  it("returns 64 bytes", async () => {
    await waitReady();
    const seed = Seed.fromBytes(new Uint8Array(32).fill(0xab));
    const sig = sr25519Sign(seed, new TextEncoder().encode("test message"));
    expect(sig.length).toBe(64);
  });

  it("differs for different messages", async () => {
    await waitReady();
    const seed = Seed.fromBytes(new Uint8Array(32).fill(0xab));
    const a = sr25519Sign(seed, new TextEncoder().encode("message one"));
    const b = sr25519Sign(seed, new TextEncoder().encode("message two"));
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
  });
});
