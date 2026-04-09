import { SampError } from "./error.js";

export class Seed {
  private constructor(private readonly bytes: Uint8Array) {}

  static fromBytes(b: Uint8Array): Seed {
    if (b.length !== 32) throw new SampError(`seed must be 32 bytes, got ${b.length}`);
    return new Seed(b);
  }

  // WHY: every caller is an audit point — grep `exposeSecret` to enumerate them.
  static exposeSecret(s: Seed): Uint8Array {
    return s.bytes;
  }

  toString(): string {
    return "Seed([REDACTED])";
  }
}

export type ViewScalar = bigint & { readonly __brand: "ViewScalar" };
export const ViewScalar = {
  fromBigInt(n: bigint): ViewScalar {
    return n as ViewScalar;
  },
  get(v: ViewScalar): bigint {
    return v;
  },
} as const;
