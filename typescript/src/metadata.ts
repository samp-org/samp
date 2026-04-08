import { decodeCompact } from "./scale.js";

const METADATA_MAGIC = 0x6174_656d;

export class MetadataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MetadataError";
  }
}

export class ScaleError extends MetadataError {
  constructor(message: string) {
    super(message);
    this.name = "ScaleError";
  }
}

export class StorageNotFoundError extends MetadataError {
  constructor(message: string) {
    super(message);
    this.name = "StorageNotFoundError";
  }
}

export class FieldNotFoundError extends MetadataError {
  constructor(message: string) {
    super(message);
    this.name = "FieldNotFoundError";
  }
}

export class StorageValueTooShortError extends MetadataError {
  constructor(message: string) {
    super(message);
    this.name = "StorageValueTooShortError";
  }
}

class Reader {
  data: Uint8Array;
  pos: number;

  constructor(data: Uint8Array) {
    this.data = data;
    this.pos = 0;
  }

  read(n: number): Uint8Array {
    if (this.pos + n > this.data.length) {
      throw new ScaleError(
        `insufficient data: need ${n} bytes at ${this.pos}, have ${this.data.length - this.pos}`,
      );
    }
    const out = this.data.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  readU8(): number {
    return this.read(1)[0];
  }

  readU32(): number {
    const b = this.read(4);
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  }

  readCompact(): number {
    const decoded = decodeCompact(this.data.subarray(this.pos));
    if (decoded === null) {
      throw new ScaleError("insufficient data for compact integer");
    }
    const [value, consumed] = decoded;
    this.pos += consumed;
    return Number(value);
  }

  readString(): string {
    const length = this.readCompact();
    const bytes = this.read(length);
    return new TextDecoder().decode(bytes);
  }

  readOptionString(): string | null {
    const tag = this.readU8();
    if (tag === 0) return null;
    if (tag === 1) return this.readString();
    throw new ScaleError(`invalid Option tag ${tag}`);
  }

  readVecString(): string[] {
    const n = this.readCompact();
    const out: string[] = [];
    for (let i = 0; i < n; i++) out.push(this.readString());
    return out;
  }

  readVecU8(): Uint8Array {
    const n = this.readCompact();
    return this.read(n);
  }

  skipStrings(): void {
    this.readVecString();
  }
}

interface Primitive {
  kind: "primitive";
  width: number;
  unsignedInt: boolean;
}

interface Composite {
  kind: "composite";
  fields: Array<[string, number]>;
}

interface ArrayShape {
  kind: "array";
  length: number;
  inner: number;
}

interface TupleShape {
  kind: "tuple";
  ids: number[];
}

interface VariantShape {
  kind: "variant";
  entries: Array<[number, string, string]>;
}

interface VariableShape {
  kind: "variable";
}

type TypeShape = Primitive | Composite | ArrayShape | TupleShape | VariantShape | VariableShape;

const VARIABLE: VariableShape = { kind: "variable" };

export interface StorageLayout {
  offset: number;
  width: number;
}

export function decodeUint(layout: StorageLayout, data: Uint8Array): bigint {
  const end = layout.offset + layout.width;
  if (data.length < end) {
    throw new StorageValueTooShortError(
      `storage value too short: need ${end} bytes, got ${data.length}`,
    );
  }
  let value = 0n;
  for (let i = 0; i < layout.width; i++) {
    value |= BigInt(data[layout.offset + i]) << BigInt(i * 8);
  }
  return value;
}

export interface ErrorEntry {
  pallet: string;
  variant: string;
  doc: string;
}

export class ErrorTable {
  byIdx: Map<string, ErrorEntry>;

  constructor() {
    this.byIdx = new Map();
  }

  humanize(palletIdx: number, errIdx: number): string | null {
    const entry = this.byIdx.get(`${palletIdx}:${errIdx}`);
    if (entry === undefined) return null;
    if (entry.doc === "") return `${entry.pallet}::${entry.variant}`;
    return `${entry.pallet}::${entry.variant}: ${entry.doc}`;
  }

  humanizeRpcError(raw: string): string {
    const payload = findAfterAny(raw, ["RPC error: ", "transaction failed: "]);
    if (payload !== null) {
      const jsonStr = trimToJson(payload);
      if (jsonStr !== null) {
        try {
          const parsed = JSON.parse(jsonStr);
          if (typeof parsed === "object" && parsed !== null) {
            const data = parsed.data;
            if (typeof data === "string") {
              const translated = this.maybeTranslateModule(data);
              return translated !== null ? translated : data;
            }
            const message = parsed.message;
            if (typeof message === "string") return message;
          }
        } catch {
          /* fallthrough */
        }
      }
    }
    const translated = this.maybeTranslateModule(raw);
    if (translated !== null) return translated;
    return raw;
  }

  private maybeTranslateModule(s: string): string | null {
    const start = s.indexOf("Module");
    if (start < 0) return null;
    const tail = s.slice(start);
    const idx = parseAfter(tail, "index:");
    const err = parseFirstByteAfter(tail, "error:");
    if (idx === null || err === null) return null;
    if (idx > 255 || err > 255) return null;
    return this.humanize(idx, err);
  }
}

function findAfterAny(s: string, needles: string[]): string | null {
  for (const n of needles) {
    const i = s.indexOf(n);
    if (i >= 0) return s.slice(i + n.length);
  }
  return null;
}

function trimToJson(s: string): string | null {
  const start = s.indexOf("{");
  if (start < 0) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < s.length; i++) {
    const b = s[i];
    if (esc) {
      esc = false;
      continue;
    }
    if (inStr && b === "\\") {
      esc = true;
      continue;
    }
    if (b === '"') {
      inStr = !inStr;
      continue;
    }
    if (inStr) continue;
    if (b === "{") depth++;
    else if (b === "}") {
      depth--;
      if (depth === 0) return s.slice(start, i + 1);
    }
  }
  return null;
}

function parseAfter(haystack: string, needle: string): number | null {
  const i = haystack.indexOf(needle);
  if (i < 0) return null;
  const rest = haystack.slice(i + needle.length);
  const m = rest.match(/^\s*(\d+)/);
  if (m === null) return null;
  return parseInt(m[1], 10);
}

function parseFirstByteAfter(haystack: string, needle: string): number | null {
  const i = haystack.indexOf(needle);
  if (i < 0) return null;
  const rest = haystack.slice(i + needle.length);
  const m = rest.match(/\[(\d+)/);
  if (m === null) return null;
  return parseInt(m[1], 10);
}

export class Metadata {
  private registry: TypeShape[];
  private storage: Map<string, number>;
  private calls: Map<string, [number, number]>;
  errors: ErrorTable;

  constructor(
    registry: TypeShape[],
    storage: Map<string, number>,
    calls: Map<string, [number, number]>,
    errors: ErrorTable,
  ) {
    this.registry = registry;
    this.storage = storage;
    this.calls = calls;
    this.errors = errors;
  }

  static fromRuntimeMetadata(data: Uint8Array): Metadata {
    const reader = new Reader(data);
    const magic = reader.readU32();
    if (magic !== METADATA_MAGIC) {
      throw new ScaleError(`metadata magic mismatch: 0x${magic.toString(16).padStart(8, "0")}`);
    }
    const version = reader.readU8();
    if (version !== 14) {
      throw new ScaleError(`metadata version ${version} unsupported (need V14)`);
    }
    const registry = readRegistry(reader);
    const { storage, pendingCalls, pendingErrors } = walkPallets(reader);
    const errors = buildErrorTable(registry, pendingErrors);
    const calls = resolveCallIndices(registry, pendingCalls);
    return new Metadata(registry, storage, calls, errors);
  }

  storageLayout(pallet: string, entry: string, fieldPath: string[]): StorageLayout {
    const valueTy = this.storage.get(`${pallet}.${entry}`);
    if (valueTy === undefined) {
      throw new StorageNotFoundError(`storage entry not found: ${pallet}.${entry}`);
    }
    let offset = 0;
    let current = valueTy;
    for (const fieldName of fieldPath) {
      const shape = this.typeAt(current);
      if (shape.kind !== "composite") {
        throw new MetadataError(`path traversal is not a composite at ${fieldName}`);
      }
      let found: number | null = null;
      for (const [name, ty] of shape.fields) {
        if (name === fieldName) {
          found = ty;
          break;
        }
        offset += this.byteSize(ty);
      }
      if (found === null) {
        throw new FieldNotFoundError(`field not found: ${fieldName}`);
      }
      current = found;
    }
    const shape = this.typeAt(current);
    if (shape.kind !== "primitive" || !shape.unsignedInt) {
      throw new MetadataError("storage_layout target is not an unsigned integer primitive");
    }
    return { offset, width: shape.width };
  }

  findCallIndex(pallet: string, call: string): [number, number] | null {
    const result = this.calls.get(`${pallet}.${call}`);
    return result === undefined ? null : result;
  }

  private typeAt(typeId: number): TypeShape {
    if (typeId < 0 || typeId >= this.registry.length) {
      throw new MetadataError(`type id ${typeId} missing from registry`);
    }
    return this.registry[typeId];
  }

  private byteSize(typeId: number): number {
    const shape = this.typeAt(typeId);
    if (shape.kind === "primitive") return shape.width;
    if (shape.kind === "composite") {
      let sum = 0;
      for (const [, ty] of shape.fields) sum += this.byteSize(ty);
      return sum;
    }
    if (shape.kind === "array") return shape.length * this.byteSize(shape.inner);
    if (shape.kind === "tuple") {
      let sum = 0;
      for (const t of shape.ids) sum += this.byteSize(t);
      return sum;
    }
    throw new MetadataError(`type id ${typeId} has variable width`);
  }
}

function readRegistry(reader: Reader): TypeShape[] {
  const n = reader.readCompact();
  const out: TypeShape[] = [];
  for (let expected = 0; expected < n; expected++) {
    const typeId = reader.readCompact();
    if (typeId !== expected) {
      throw new ScaleError(`non-sequential type id ${typeId} (expected ${expected})`);
    }
    reader.skipStrings();
    skipTypeParams(reader);
    out.push(readTypeDef(reader));
    reader.skipStrings();
  }
  return out;
}

function readTypeDef(reader: Reader): TypeShape {
  const tag = reader.readU8();
  if (tag === 0) return { kind: "composite", fields: readFields(reader) };
  if (tag === 1) {
    const n = reader.readCompact();
    const entries: Array<[number, string, string]> = [];
    for (let i = 0; i < n; i++) {
      const name = reader.readString();
      readFields(reader);
      const index = reader.readU8();
      const docs = reader.readVecString();
      let doc = "";
      for (const d of docs) {
        const trimmed = d.trim();
        if (trimmed !== "") {
          doc = trimmed;
          break;
        }
      }
      entries.push([index, name, doc]);
    }
    return { kind: "variant", entries };
  }
  if (tag === 2) {
    reader.readCompact();
    return VARIABLE;
  }
  if (tag === 3) {
    const length = reader.readU32();
    const inner = reader.readCompact();
    return { kind: "array", length, inner };
  }
  if (tag === 4) {
    const n = reader.readCompact();
    const ids: number[] = [];
    for (let i = 0; i < n; i++) ids.push(reader.readCompact());
    return { kind: "tuple", ids };
  }
  if (tag === 5) return primitiveShape(reader.readU8());
  if (tag === 6) {
    reader.readCompact();
    return VARIABLE;
  }
  if (tag === 7) {
    reader.readCompact();
    reader.readCompact();
    return VARIABLE;
  }
  throw new ScaleError(`unknown TypeDef tag ${tag}`);
}

function readFields(reader: Reader): Array<[string, number]> {
  const n = reader.readCompact();
  const out: Array<[string, number]> = [];
  for (let i = 0; i < n; i++) {
    const name = reader.readOptionString() ?? "";
    const ty = reader.readCompact();
    reader.readOptionString();
    reader.skipStrings();
    out.push([name, ty]);
  }
  return out;
}

function skipTypeParams(reader: Reader): void {
  const n = reader.readCompact();
  for (let i = 0; i < n; i++) {
    reader.readString();
    const tag = reader.readU8();
    if (tag === 0) continue;
    if (tag === 1) {
      reader.readCompact();
      continue;
    }
    throw new ScaleError(`invalid Option tag ${tag}`);
  }
}

function primitiveShape(tag: number): TypeShape {
  const table: Record<number, [number, boolean]> = {
    0: [1, false],
    1: [4, false],
    3: [1, true],
    4: [2, true],
    5: [4, true],
    6: [8, true],
    7: [16, true],
    8: [32, true],
    9: [1, false],
    10: [2, false],
    11: [4, false],
    12: [8, false],
    13: [16, false],
    14: [32, false],
  };
  if (tag === 2) return VARIABLE;
  if (!(tag in table)) throw new ScaleError(`unknown primitive tag ${tag}`);
  const [width, unsignedInt] = table[tag];
  return { kind: "primitive", width, unsignedInt };
}

interface PalletWalkResult {
  storage: Map<string, number>;
  pendingCalls: Array<[string, number, number]>;
  pendingErrors: Array<[string, number, number]>;
}

function walkPallets(reader: Reader): PalletWalkResult {
  const storage = new Map<string, number>();
  const pendingCalls: Array<[string, number, number]> = [];
  const pendingErrors: Array<[string, number, number]> = [];

  const n = reader.readCompact();
  for (let i = 0; i < n; i++) {
    const palletName = reader.readString();

    if (optionTag(reader)) {
      reader.readString();
      const entryCount = reader.readCompact();
      for (let j = 0; j < entryCount; j++) {
        const entryName = reader.readString();
        reader.readU8();
        const valueTy = readStorageEntryValueType(reader);
        storage.set(`${palletName}.${entryName}`, valueTy);
        reader.readVecU8();
        reader.skipStrings();
      }
    }

    const callsTy = optionTag(reader) ? reader.readCompact() : null;
    skipOptionalCompact(reader);

    const constCount = reader.readCompact();
    for (let j = 0; j < constCount; j++) {
      reader.readString();
      reader.readCompact();
      reader.readVecU8();
      reader.skipStrings();
    }

    const errorTy = optionTag(reader) ? reader.readCompact() : null;
    const palletIndex = reader.readU8();

    if (callsTy !== null) pendingCalls.push([palletName, palletIndex, callsTy]);
    if (errorTy !== null) pendingErrors.push([palletName, palletIndex, errorTy]);
  }

  return { storage, pendingCalls, pendingErrors };
}

function readStorageEntryValueType(reader: Reader): number {
  const tag = reader.readU8();
  if (tag === 0) return reader.readCompact();
  if (tag === 1) {
    const n = reader.readCompact();
    for (let i = 0; i < n; i++) reader.readU8();
    reader.readCompact();
    return reader.readCompact();
  }
  throw new ScaleError(`unknown StorageEntryType tag ${tag}`);
}

function optionTag(reader: Reader): boolean {
  const tag = reader.readU8();
  if (tag === 0) return false;
  if (tag === 1) return true;
  throw new ScaleError(`invalid Option tag ${tag}`);
}

function skipOptionalCompact(reader: Reader): void {
  if (optionTag(reader)) reader.readCompact();
}

function buildErrorTable(
  registry: TypeShape[],
  pending: Array<[string, number, number]>,
): ErrorTable {
  const table = new ErrorTable();
  for (const [palletName, palletIdx, errorTy] of pending) {
    if (errorTy < 0 || errorTy >= registry.length) continue;
    const shape = registry[errorTy];
    if (shape.kind !== "variant") continue;
    for (const [variantIdx, variantName, doc] of shape.entries) {
      table.byIdx.set(`${palletIdx}:${variantIdx}`, {
        pallet: palletName,
        variant: variantName,
        doc,
      });
    }
  }
  return table;
}

function resolveCallIndices(
  registry: TypeShape[],
  pending: Array<[string, number, number]>,
): Map<string, [number, number]> {
  const out = new Map<string, [number, number]>();
  for (const [palletName, palletIdx, callsTy] of pending) {
    if (callsTy < 0 || callsTy >= registry.length) continue;
    const shape = registry[callsTy];
    if (shape.kind !== "variant") continue;
    for (const [callIdx, callName] of shape.entries) {
      out.set(`${palletName}.${callName}`, [palletIdx, callIdx]);
    }
  }
  return out;
}
