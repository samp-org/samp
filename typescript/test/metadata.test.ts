import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  ErrorTable,
  FieldNotFoundError,
  Metadata,
  ScaleError,
  StorageNotFoundError,
  decodeUint,
} from "../src/metadata.js";

function polkadotMetadataBytes(): Uint8Array {
  const raw = readFileSync(
    resolve(__dirname, "../../e2e/fixtures/polkadot_metadata_v14.scale"),
  );
  const out = new Uint8Array(raw.length + 4);
  out.set(new TextEncoder().encode("meta"), 0);
  out.set(raw, 4);
  return out;
}

describe("metadata", () => {
  it("rejects empty input", () => {
    expect(() => Metadata.fromRuntimeMetadata(new Uint8Array())).toThrow(ScaleError);
  });

  it("rejects wrong magic", () => {
    expect(() =>
      Metadata.fromRuntimeMetadata(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x0e])),
    ).toThrow(/magic/);
  });

  it("rejects wrong version", () => {
    const bytes = new Uint8Array([0x6d, 0x65, 0x74, 0x61, 0x0d]);
    expect(() => Metadata.fromRuntimeMetadata(bytes)).toThrow(/version/);
  });

  it("rejects truncated input after magic", () => {
    const bytes = new Uint8Array([0x6d, 0x65, 0x74, 0x61]);
    expect(() => Metadata.fromRuntimeMetadata(bytes)).toThrow(ScaleError);
  });

  it("parses real polkadot v14 metadata", () => {
    Metadata.fromRuntimeMetadata(polkadotMetadataBytes());
  });

  it("resolves System.Account.data.free storage layout", () => {
    const metadata = Metadata.fromRuntimeMetadata(polkadotMetadataBytes());
    const layout = metadata.storageLayout("System", "Account", ["data", "free"]);
    expect([8, 16]).toContain(layout.width);
  });

  it("finds System.remark call index", () => {
    const metadata = Metadata.fromRuntimeMetadata(polkadotMetadataBytes());
    const result = metadata.findCallIndex("System", "remark");
    expect(result).not.toBeNull();
    if (result === null) return;
    expect(result[0]).toEqual(0);
  });

  it("finds System.remark_with_event call index", () => {
    const metadata = Metadata.fromRuntimeMetadata(polkadotMetadataBytes());
    expect(metadata.findCallIndex("System", "remark_with_event")).not.toBeNull();
  });

  it("throws StorageNotFoundError for unknown pallet", () => {
    const metadata = Metadata.fromRuntimeMetadata(polkadotMetadataBytes());
    expect(() => metadata.storageLayout("DoesNotExist", "Foo", ["bar"])).toThrow(
      StorageNotFoundError,
    );
  });

  it("throws FieldNotFoundError for unknown field", () => {
    const metadata = Metadata.fromRuntimeMetadata(polkadotMetadataBytes());
    expect(() =>
      metadata.storageLayout("System", "Account", ["data", "nonexistent_field"]),
    ).toThrow(FieldNotFoundError);
  });

  it("returns null for unknown call name", () => {
    const metadata = Metadata.fromRuntimeMetadata(polkadotMetadataBytes());
    expect(metadata.findCallIndex("System", "definitely_not_a_call")).toBeNull();
  });

  it("decodes a uint at the resolved layout", () => {
    const metadata = Metadata.fromRuntimeMetadata(polkadotMetadataBytes());
    const layout = metadata.storageLayout("System", "Account", ["data", "free"]);
    const value = 12345678n;
    const buf = new Uint8Array(layout.offset + layout.width + 16);
    let v = value;
    for (let i = 0; i < layout.width; i++) {
      buf[layout.offset + i] = Number(v & 0xffn);
      v >>= 8n;
    }
    expect(decodeUint(layout, buf)).toEqual(value);
  });
});

describe("error table", () => {
  it("passes through unparseable input", () => {
    const t = new ErrorTable();
    expect(t.humanizeRpcError("not json at all")).toEqual("not json at all");
  });

  it("extracts data field from rpc error envelope", () => {
    const t = new ErrorTable();
    const raw =
      'RPC error: {"code":1010,"data":"Transaction has a bad signature","message":"Invalid"}';
    expect(t.humanizeRpcError(raw)).toEqual("Transaction has a bad signature");
  });

  it("falls back to message field", () => {
    const t = new ErrorTable();
    const raw = 'RPC error: {"code":1010,"message":"Invalid Transaction"}';
    expect(t.humanizeRpcError(raw)).toEqual("Invalid Transaction");
  });

  it("returns null for unknown variant", () => {
    const t = new ErrorTable();
    expect(t.humanize(99, 99)).toBeNull();
  });
});
