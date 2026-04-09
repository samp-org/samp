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

type Brand<T, B> = T & { readonly __brand: B };

export type ViewScalar = Brand<Uint8Array, "ViewScalar">;
export const ViewScalar = {
  fromBytes(b: Uint8Array): ViewScalar {
    if (b.length !== 32) throw new SampError(`view_scalar must be 32 bytes, got ${b.length}`);
    return b as ViewScalar;
  },
  exposeSecret(v: ViewScalar): Uint8Array {
    return v;
  },
} as const;

export type ContentKey = Brand<Uint8Array, "ContentKey">;
export const ContentKey = {
  fromBytes(b: Uint8Array): ContentKey {
    if (b.length !== 32) throw new SampError(`content_key must be 32 bytes, got ${b.length}`);
    return b as ContentKey;
  },
  exposeSecret(c: ContentKey): Uint8Array {
    return c;
  },
} as const;
