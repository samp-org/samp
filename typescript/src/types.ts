import { SampError } from "./error.js";

export const CAPSULE_SIZE = 33;
export const CHANNEL_NAME_MAX = 32;
export const CHANNEL_DESC_MAX = 128;

type Brand<T, B> = T & { readonly __brand: B };

// 32-byte opaques

export type Pubkey = Brand<Uint8Array, "Pubkey">;
export const Pubkey = {
  fromBytes(b: Uint8Array): Pubkey {
    if (b.length !== 32) throw new SampError(`pubkey must be 32 bytes, got ${b.length}`);
    return b as Pubkey;
  },
  zero(): Pubkey {
    return new Uint8Array(32) as Pubkey;
  },
} as const;

export type EphPubkey = Brand<Uint8Array, "EphPubkey">;
export const EphPubkey = {
  fromBytes(b: Uint8Array): EphPubkey {
    if (b.length !== 32) throw new SampError(`eph_pubkey must be 32 bytes, got ${b.length}`);
    return b as EphPubkey;
  },
} as const;

export type GenesisHash = Brand<Uint8Array, "GenesisHash">;
export const GenesisHash = {
  fromBytes(b: Uint8Array): GenesisHash {
    if (b.length !== 32) throw new SampError(`genesis_hash must be 32 bytes, got ${b.length}`);
    return b as GenesisHash;
  },
} as const;

// 64-byte opaque

export type Signature = Brand<Uint8Array, "Signature">;
export const Signature = {
  fromBytes(b: Uint8Array): Signature {
    if (b.length !== 64) throw new SampError(`signature must be 64 bytes, got ${b.length}`);
    return b as Signature;
  },
} as const;

// 12-byte opaque (ChaCha20 IV)

export type Nonce = Brand<Uint8Array, "Nonce">;
export const Nonce = {
  fromBytes(b: Uint8Array): Nonce {
    if (b.length !== 12) throw new SampError(`nonce must be 12 bytes, got ${b.length}`);
    return b as Nonce;
  },
  zero(): Nonce {
    return new Uint8Array(12) as Nonce;
  },
  // WHY: ChaCha20 AEAD boundary — only crypto.ts reads the raw 12 bytes.
  chachaBytes(n: Nonce): Uint8Array {
    return n;
  },
} as const;

// variable-length opaques

export type Plaintext = Brand<Uint8Array, "Plaintext">;
export const Plaintext = {
  fromBytes(b: Uint8Array): Plaintext {
    return b as Plaintext;
  },
  asBytes(p: Plaintext): Uint8Array {
    return p;
  },
} as const;

export type Ciphertext = Brand<Uint8Array, "Ciphertext">;
export const Ciphertext = {
  fromBytes(b: Uint8Array): Ciphertext {
    return b as Ciphertext;
  },
  asBytes(c: Ciphertext): Uint8Array {
    return c;
  },
} as const;

export type Capsules = Brand<Uint8Array, "Capsules">;
export const Capsules = {
  fromBytes(b: Uint8Array): Capsules {
    if (b.length % CAPSULE_SIZE !== 0) {
      throw new SampError(`capsule length not multiple of ${CAPSULE_SIZE}: ${b.length}`);
    }
    return b as Capsules;
  },
  asBytes(c: Capsules): Uint8Array {
    return c;
  },
  count(c: Capsules): number {
    return c.length / CAPSULE_SIZE;
  },
} as const;

export type RemarkBytes = Brand<Uint8Array, "RemarkBytes">;
export const RemarkBytes = {
  fromBytes(b: Uint8Array): RemarkBytes {
    return b as RemarkBytes;
  },
  asBytes(r: RemarkBytes): Uint8Array {
    return r;
  },
} as const;

export type ExtrinsicBytes = Brand<Uint8Array, "ExtrinsicBytes">;
export const ExtrinsicBytes = {
  fromBytes(b: Uint8Array): ExtrinsicBytes {
    return b as ExtrinsicBytes;
  },
  asBytes(e: ExtrinsicBytes): Uint8Array {
    return e;
  },
} as const;

export type CallArgs = Brand<Uint8Array, "CallArgs">;
export const CallArgs = {
  fromBytes(b: Uint8Array): CallArgs {
    return b as CallArgs;
  },
  asBytes(c: CallArgs): Uint8Array {
    return c;
  },
} as const;

// Branded numerics

export type BlockNumber = Brand<number, "BlockNumber">;
export const BlockNumber = {
  from(n: number): BlockNumber {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
      throw new SampError(`block number out of u32 range: ${n}`);
    }
    return n as BlockNumber;
  },
  get(b: BlockNumber): number {
    return b;
  },
  zero(): BlockNumber {
    return 0 as BlockNumber;
  },
} as const;

export type ExtIndex = Brand<number, "ExtIndex">;
export const ExtIndex = {
  from(n: number): ExtIndex {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
      throw new SampError(`ext index out of u16 range: ${n}`);
    }
    return n as ExtIndex;
  },
  get(e: ExtIndex): number {
    return e;
  },
  zero(): ExtIndex {
    return 0 as ExtIndex;
  },
} as const;

export type ExtrinsicNonce = Brand<number, "ExtrinsicNonce">;
export const ExtrinsicNonce = {
  from(n: number): ExtrinsicNonce {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
      throw new SampError(`extrinsic nonce out of u32 range: ${n}`);
    }
    return n as ExtrinsicNonce;
  },
  get(e: ExtrinsicNonce): number {
    return e;
  },
} as const;

export type SpecVersion = Brand<number, "SpecVersion">;
export const SpecVersion = {
  from(n: number): SpecVersion {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
      throw new SampError(`spec version out of u32 range: ${n}`);
    }
    return n as SpecVersion;
  },
  get(s: SpecVersion): number {
    return s;
  },
} as const;

export type TxVersion = Brand<number, "TxVersion">;
export const TxVersion = {
  from(n: number): TxVersion {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
      throw new SampError(`tx version out of u32 range: ${n}`);
    }
    return n as TxVersion;
  },
  get(t: TxVersion): number {
    return t;
  },
} as const;

export type PalletIdx = Brand<number, "PalletIdx">;
export const PalletIdx = {
  from(n: number): PalletIdx {
    if (!Number.isInteger(n) || n < 0 || n > 0xff) {
      throw new SampError(`pallet idx out of u8 range: ${n}`);
    }
    return n as PalletIdx;
  },
  get(p: PalletIdx): number {
    return p;
  },
} as const;

export type CallIdx = Brand<number, "CallIdx">;
export const CallIdx = {
  from(n: number): CallIdx {
    if (!Number.isInteger(n) || n < 0 || n > 0xff) {
      throw new SampError(`call idx out of u8 range: ${n}`);
    }
    return n as CallIdx;
  },
  get(c: CallIdx): number {
    return c;
  },
} as const;

export type ViewTag = Brand<number, "ViewTag">;
export const ViewTag = {
  from(n: number): ViewTag {
    if (!Number.isInteger(n) || n < 0 || n > 0xff) {
      throw new SampError(`view tag out of u8 range: ${n}`);
    }
    return n as ViewTag;
  },
  get(v: ViewTag): number {
    return v;
  },
} as const;

export type Ss58Prefix = Brand<number, "Ss58Prefix">;
export const Ss58Prefix = {
  SUBSTRATE_GENERIC: 42 as Brand<number, "Ss58Prefix">,
  POLKADOT: 0 as Brand<number, "Ss58Prefix">,
  KUSAMA: 2 as Brand<number, "Ss58Prefix">,
  from(n: number): Ss58Prefix {
    if (!Number.isInteger(n) || n < 0 || n > 63) {
      throw new SampError(`ss58 prefix unsupported: ${n}`);
    }
    return n as Ss58Prefix;
  },
  get(p: Ss58Prefix): number {
    return p;
  },
} as const;

// BlockRef

export class BlockRef {
  private constructor(
    readonly block: BlockNumber,
    readonly index: ExtIndex,
  ) {}

  static of(block: BlockNumber, index: ExtIndex): BlockRef {
    return new BlockRef(block, index);
  }

  static fromParts(block: number, index: number): BlockRef {
    return new BlockRef(BlockNumber.from(block), ExtIndex.from(index));
  }

  static zero(): BlockRef {
    return new BlockRef(BlockNumber.zero(), ExtIndex.zero());
  }

  isZero(): boolean {
    return (this.block as number) === 0 && (this.index as number) === 0;
  }

  toString(): string {
    return `#${this.block as number}.${this.index as number}`;
  }
}

// Validated strings

export class ChannelName {
  private constructor(private readonly s: string) {}

  static parse(s: string): ChannelName {
    const n = new TextEncoder().encode(s).length;
    if (n === 0 || n > CHANNEL_NAME_MAX) {
      throw new SampError(`channel name must be 1-${CHANNEL_NAME_MAX} bytes`);
    }
    return new ChannelName(s);
  }

  asString(): string {
    return this.s;
  }

  byteLength(): number {
    return new TextEncoder().encode(this.s).length;
  }
}

export class ChannelDescription {
  private constructor(private readonly s: string) {}

  static parse(s: string): ChannelDescription {
    const n = new TextEncoder().encode(s).length;
    if (n > CHANNEL_DESC_MAX) {
      throw new SampError(`channel description must be 0-${CHANNEL_DESC_MAX} bytes`);
    }
    return new ChannelDescription(s);
  }

  asString(): string {
    return this.s;
  }

  byteLength(): number {
    return new TextEncoder().encode(this.s).length;
  }
}

// Ss58Address (runtime state — class)

export class Ss58Address {
  private constructor(
    private readonly address: string,
    private readonly pk: Pubkey,
    private readonly pfx: Ss58Prefix,
  ) {}

  static fromParts(address: string, pubkey: Pubkey, prefix: Ss58Prefix): Ss58Address {
    return new Ss58Address(address, pubkey, prefix);
  }

  static parse(s: string): Ss58Address {
    // Deferred to ss58.ts to avoid circular import at module-eval time.
    return ss58ParseImpl(s);
  }

  static encode(pubkey: Pubkey, prefix: Ss58Prefix): Ss58Address {
    return ss58EncodeImpl(pubkey, prefix);
  }

  asString(): string {
    return this.address;
  }

  pubkey(): Pubkey {
    return this.pk;
  }

  prefix(): Ss58Prefix {
    return this.pfx;
  }
}

// Late-bound to break the import cycle with ss58.ts. Populated by ss58.ts at
// module init; unreachable until ss58.ts has been imported once.
let ss58ParseImpl: (s: string) => Ss58Address = () => {
  throw new SampError("ss58 module not initialized");
};
let ss58EncodeImpl: (pubkey: Pubkey, prefix: Ss58Prefix) => Ss58Address = () => {
  throw new SampError("ss58 module not initialized");
};

export function __registerSs58(
  parse: (s: string) => Ss58Address,
  encode: (pubkey: Pubkey, prefix: Ss58Prefix) => Ss58Address,
): void {
  ss58ParseImpl = parse;
  ss58EncodeImpl = encode;
}
