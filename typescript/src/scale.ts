export function decodeCompact(data: Uint8Array): [bigint, number] | null {
  if (data.length === 0) return null;
  const mode = data[0] & 0b11;
  if (mode === 0b00) {
    return [BigInt(data[0] >> 2), 1];
  }
  if (mode === 0b01) {
    if (data.length < 2) return null;
    const raw = data[0] | (data[1] << 8);
    return [BigInt(raw >> 2), 2];
  }
  if (mode === 0b10) {
    if (data.length < 4) return null;
    const raw =
      (data[0] >>> 0) |
      ((data[1] >>> 0) << 8) |
      ((data[2] >>> 0) << 16) |
      ((data[3] >>> 0) << 24);
    return [BigInt(raw >>> 2), 4];
  }
  const bytesFollowing = (data[0] >> 2) + 4;
  if (data.length < 1 + bytesFollowing) return null;
  let value = 0n;
  for (let i = 0; i < bytesFollowing; i++) {
    value |= BigInt(data[1 + i]) << BigInt(i * 8);
  }
  return [value, 1 + bytesFollowing];
}

export function encodeCompact(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("compact integers are unsigned");
  if (value < 64n) {
    return new Uint8Array([Number(value) << 2]);
  }
  if (value < 16_384n) {
    const v = (Number(value) << 2) | 0b01;
    return new Uint8Array([v & 0xff, (v >> 8) & 0xff]);
  }
  if (value < 1n << 30n) {
    const v = (Number(value) << 2) | 0b10;
    return new Uint8Array([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]);
  }
  let raw: number[] = [];
  let v = value;
  while (v > 0n) {
    raw.push(Number(v & 0xffn));
    v >>= 8n;
  }
  while (raw.length < 4) raw.push(0);
  const n = raw.length;
  const prefix = (((n - 4) << 2) | 0b11) & 0xff;
  return new Uint8Array([prefix, ...raw]);
}

export function decodeBytes(data: Uint8Array): [Uint8Array, number] | null {
  const decoded = decodeCompact(data);
  if (decoded === null) return null;
  const [length, prefixLen] = decoded;
  const len = Number(length);
  const end = prefixLen + len;
  if (data.length < end) return null;
  return [data.subarray(prefixLen, end), end];
}
