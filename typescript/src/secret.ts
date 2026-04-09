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

export class ViewScalar {
  private constructor(private readonly bytes: Uint8Array) {}

  static fromBytes(b: Uint8Array): ViewScalar {
    if (b.length !== 32) throw new SampError(`view_scalar must be 32 bytes, got ${b.length}`);
    return new ViewScalar(b);
  }

  static exposeSecret(v: ViewScalar): Uint8Array {
    return v.bytes;
  }

  toString(): string {
    return "ViewScalar([REDACTED])";
  }
}

export class ContentKey {
  private constructor(private readonly bytes: Uint8Array) {}

  static fromBytes(b: Uint8Array): ContentKey {
    if (b.length !== 32) throw new SampError(`content_key must be 32 bytes, got ${b.length}`);
    return new ContentKey(b);
  }

  static exposeSecret(c: ContentKey): Uint8Array {
    return c.bytes;
  }

  toString(): string {
    return "ContentKey([REDACTED])";
  }
}
