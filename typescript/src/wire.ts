import { SampError } from "./error.js";

export const SAMP_VERSION = 0x10;
export const CONTENT_TYPE_PUBLIC = 0x10;
export const CONTENT_TYPE_ENCRYPTED = 0x11;
export const CONTENT_TYPE_THREAD = 0x12;
export const CONTENT_TYPE_CHANNEL_CREATE = 0x13;
export const CONTENT_TYPE_CHANNEL = 0x14;
export const CONTENT_TYPE_GROUP = 0x15;

export const THREAD_HEADER_SIZE = 18;
export const CHANNEL_HEADER_SIZE = 12;
export const CHANNEL_NAME_MAX = 32;
export const CHANNEL_DESC_MAX = 128;
export const CAPSULE_SIZE = 33;

export interface BlockRef {
  block: number;
  index: number;
}

export const BLOCK_REF_ZERO: BlockRef = { block: 0, index: 0 };

export interface Remark {
  contentType: number;
  recipient: Uint8Array;
  viewTag: number;
  nonce: Uint8Array;
  content: Uint8Array;
}

function encodeBlockRef(out: Uint8Array, offset: number, ref_: BlockRef): void {
  const dv = new DataView(out.buffer, out.byteOffset);
  dv.setUint32(offset, ref_.block, true);
  dv.setUint16(offset + 4, ref_.index, true);
}

function decodeBlockRef(data: Uint8Array, offset: number): BlockRef {
  const dv = new DataView(data.buffer, data.byteOffset);
  return {
    block: dv.getUint32(offset, true),
    index: dv.getUint16(offset + 4, true),
  };
}

export function encodePublic(recipient: Uint8Array, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + 32 + body.length);
  out[0] = CONTENT_TYPE_PUBLIC;
  out.set(recipient, 1);
  out.set(body, 33);
  return out;
}

export function encodeEncrypted(
  contentType: number,
  viewTag: number,
  nonce: Uint8Array,
  content: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(2 + 12 + content.length);
  out[0] = contentType;
  out[1] = viewTag;
  out.set(nonce, 2);
  out.set(content, 14);
  return out;
}

export function encodeChannelMsg(
  channelRef: BlockRef,
  replyTo: BlockRef,
  continues: BlockRef,
  body: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(19 + body.length);
  out[0] = CONTENT_TYPE_CHANNEL;
  encodeBlockRef(out, 1, channelRef);
  encodeBlockRef(out, 7, replyTo);
  encodeBlockRef(out, 13, continues);
  out.set(body, 19);
  return out;
}

export function encodeChannelCreate(name: string, description: string): Uint8Array {
  const nb = new TextEncoder().encode(name);
  const db = new TextEncoder().encode(description);
  if (nb.length === 0 || nb.length > CHANNEL_NAME_MAX) throw new SampError(`channel name must be 1-${CHANNEL_NAME_MAX} bytes`);
  if (db.length > CHANNEL_DESC_MAX) throw new SampError(`channel description must be 0-${CHANNEL_DESC_MAX} bytes`);
  const out = new Uint8Array(3 + nb.length + db.length);
  out[0] = CONTENT_TYPE_CHANNEL_CREATE;
  out[1] = nb.length;
  out.set(nb, 2);
  out[2 + nb.length] = db.length;
  out.set(db, 3 + nb.length);
  return out;
}

export function encodeGroup(
  nonce: Uint8Array,
  ephPubkey: Uint8Array,
  capsules: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(45 + capsules.length + ciphertext.length);
  out[0] = CONTENT_TYPE_GROUP;
  out.set(nonce, 1);
  out.set(ephPubkey, 13);
  out.set(capsules, 45);
  out.set(ciphertext, 45 + capsules.length);
  return out;
}

export function decodeRemark(data: Uint8Array): Remark {
  if (data.length === 0) throw new SampError("insufficient data");
  const ct = data[0];
  if ((ct & 0xf0) !== SAMP_VERSION) {
    throw new SampError(`unsupported version: 0x${(ct & 0xf0).toString(16).padStart(2, "0")}`);
  }
  const lower = ct & 0x0f;

  if (lower === 0x00) {
    if (data.length < 33) throw new SampError("insufficient data for public message");
    const body = data.slice(33);
    new TextDecoder("utf-8", { fatal: true }).decode(body);
    return {
      contentType: ct,
      recipient: data.slice(1, 33),
      viewTag: 0,
      nonce: new Uint8Array(12),
      content: body,
    };
  }

  if (lower === 0x01 || lower === 0x02) {
    if (data.length < 14) throw new SampError("insufficient data for encrypted message");
    return {
      contentType: ct,
      recipient: new Uint8Array(32),
      viewTag: data[1],
      nonce: data.slice(2, 14),
      content: data.slice(14),
    };
  }

  if (lower === 0x03) {
    return {
      contentType: ct,
      recipient: new Uint8Array(32),
      viewTag: 0,
      nonce: new Uint8Array(12),
      content: data.slice(1),
    };
  }

  if (lower === 0x04) {
    if (data.length < 19) throw new SampError("insufficient data for channel message");
    const ref_ = decodeBlockRef(data, 1);
    const recipient = new Uint8Array(32);
    const dv = new DataView(recipient.buffer);
    dv.setUint32(0, ref_.block, true);
    dv.setUint16(4, ref_.index, true);
    return {
      contentType: ct,
      recipient,
      viewTag: 0,
      nonce: new Uint8Array(12),
      content: data.slice(7),
    };
  }

  if (lower === 0x05) {
    if (data.length < 45) throw new SampError("insufficient data for group message");
    return {
      contentType: ct,
      recipient: new Uint8Array(32),
      viewTag: 0,
      nonce: data.slice(1, 13),
      content: data.slice(13),
    };
  }

  throw new SampError(`reserved content type: 0x${ct.toString(16)}`);
}

export function encodeThreadContent(
  thread: BlockRef,
  replyTo: BlockRef,
  continues: BlockRef,
  body: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(THREAD_HEADER_SIZE + body.length);
  encodeBlockRef(out, 0, thread);
  encodeBlockRef(out, 6, replyTo);
  encodeBlockRef(out, 12, continues);
  out.set(body, 18);
  return out;
}

export function decodeThreadContent(
  content: Uint8Array,
): { thread: BlockRef; replyTo: BlockRef; continues: BlockRef; body: Uint8Array } {
  if (content.length < THREAD_HEADER_SIZE) throw new SampError("insufficient data for thread header");
  return {
    thread: decodeBlockRef(content, 0),
    replyTo: decodeBlockRef(content, 6),
    continues: decodeBlockRef(content, 12),
    body: content.slice(18),
  };
}

export function encodeChannelContent(
  replyTo: BlockRef,
  continues: BlockRef,
  body: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(CHANNEL_HEADER_SIZE + body.length);
  encodeBlockRef(out, 0, replyTo);
  encodeBlockRef(out, 6, continues);
  out.set(body, 12);
  return out;
}

export function decodeChannelContent(
  content: Uint8Array,
): { replyTo: BlockRef; continues: BlockRef; body: Uint8Array } {
  if (content.length < CHANNEL_HEADER_SIZE) throw new SampError("insufficient data for channel header");
  return {
    replyTo: decodeBlockRef(content, 0),
    continues: decodeBlockRef(content, 6),
    body: content.slice(12),
  };
}

export function decodeGroupContent(
  content: Uint8Array,
): { groupRef: BlockRef; replyTo: BlockRef; continues: BlockRef; body: Uint8Array } {
  if (content.length < THREAD_HEADER_SIZE) throw new SampError("insufficient data for group content header");
  return {
    groupRef: decodeBlockRef(content, 0),
    replyTo: decodeBlockRef(content, 6),
    continues: decodeBlockRef(content, 12),
    body: content.slice(18),
  };
}

export function channelRefFromRecipient(recipient: Uint8Array): BlockRef {
  const dv = new DataView(recipient.buffer, recipient.byteOffset);
  return {
    block: dv.getUint32(0, true),
    index: dv.getUint16(4, true),
  };
}

export function encodeGroupMembers(memberPubkeys: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(1 + memberPubkeys.length * 32);
  out[0] = memberPubkeys.length;
  for (let i = 0; i < memberPubkeys.length; i++) {
    out.set(memberPubkeys[i], 1 + i * 32);
  }
  return out;
}

export function decodeGroupMembers(data: Uint8Array): { members: Uint8Array[]; body: Uint8Array } {
  if (data.length < 1) throw new SampError("insufficient data for group members");
  const count = data[0];
  const expected = 1 + count * 32;
  if (data.length < expected) throw new SampError("insufficient data for group members");
  const members: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    members.push(data.slice(1 + i * 32, 1 + (i + 1) * 32));
  }
  return { members, body: data.slice(expected) };
}

export function decodeChannelCreate(data: Uint8Array): { name: string; description: string } {
  if (data.length < 2) throw new SampError("insufficient data for channel create");
  const nameLen = data[0];
  if (nameLen === 0 || nameLen > CHANNEL_NAME_MAX) throw new SampError(`channel name must be 1-${CHANNEL_NAME_MAX} bytes`);
  if (data.length < 1 + nameLen + 1) throw new SampError("insufficient data for channel name");
  const name = new TextDecoder().decode(data.slice(1, 1 + nameLen));
  const descOff = 1 + nameLen;
  const descLen = data[descOff];
  if (descLen > CHANNEL_DESC_MAX) throw new SampError(`channel description must be 0-${CHANNEL_DESC_MAX} bytes`);
  if (data.length < descOff + 1 + descLen) throw new SampError("insufficient data for channel description");
  const description = new TextDecoder().decode(data.slice(descOff + 1, descOff + 1 + descLen));
  return { name, description };
}
