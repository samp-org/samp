import { SampError } from "./error.js";
import {
  BlockNumber,
  BlockRef,
  CAPSULE_SIZE,
  CHANNEL_DESC_MAX,
  CHANNEL_NAME_MAX,
  Capsules,
  ChannelDescription,
  ChannelName,
  Ciphertext,
  EphPubkey,
  ExtIndex,
  Nonce,
  Pubkey,
  RemarkBytes,
  ViewTag,
} from "./types.js";

export { CAPSULE_SIZE, CHANNEL_NAME_MAX, CHANNEL_DESC_MAX };
export const SAMP_VERSION = 0x10;
export const THREAD_HEADER_SIZE = 18;
export const CHANNEL_HEADER_SIZE = 12;

export enum ContentType {
  Public = 0x10,
  Encrypted = 0x11,
  Thread = 0x12,
  ChannelCreate = 0x13,
  Channel = 0x14,
  Group = 0x15,
  Application = 0x18,
}

export function contentTypeFromByte(b: number): ContentType {
  if ((b & 0xf0) !== SAMP_VERSION) {
    throw new SampError(`unsupported version: 0x${(b & 0xf0).toString(16).padStart(2, "0")}`);
  }
  switch (b & 0x0f) {
    case 0x00:
      return ContentType.Public;
    case 0x01:
      return ContentType.Encrypted;
    case 0x02:
      return ContentType.Thread;
    case 0x03:
      return ContentType.ChannelCreate;
    case 0x04:
      return ContentType.Channel;
    case 0x05:
      return ContentType.Group;
    case 0x06:
    case 0x07:
      throw new SampError(`reserved content type: 0x${b.toString(16)}`);
    default:
      return ContentType.Application;
  }
}

export type Remark =
  | { readonly type: ContentType.Public; readonly recipient: Pubkey; readonly body: string }
  | {
      readonly type: ContentType.Encrypted;
      readonly viewTag: ViewTag;
      readonly nonce: Nonce;
      readonly ciphertext: Ciphertext;
    }
  | {
      readonly type: ContentType.Thread;
      readonly viewTag: ViewTag;
      readonly nonce: Nonce;
      readonly ciphertext: Ciphertext;
    }
  | {
      readonly type: ContentType.ChannelCreate;
      readonly name: ChannelName;
      readonly description: ChannelDescription;
    }
  | {
      readonly type: ContentType.Channel;
      readonly channelRef: BlockRef;
      readonly replyTo: BlockRef;
      readonly continues: BlockRef;
      readonly body: string;
    }
  | { readonly type: ContentType.Group; readonly nonce: Nonce; readonly content: Uint8Array }
  | { readonly type: ContentType.Application; readonly tag: number; readonly payload: Uint8Array };

export function isSampRemark(bytes: Uint8Array): boolean {
  return bytes.length > 0 && (bytes[0]! & 0xf0) === SAMP_VERSION;
}

function writeBlockRef(out: Uint8Array, offset: number, ref: BlockRef): void {
  const dv = new DataView(out.buffer, out.byteOffset);
  dv.setUint32(offset, BlockNumber.get(ref.block), true);
  dv.setUint16(offset + 4, ExtIndex.get(ref.index), true);
}

function readBlockRef(data: Uint8Array, offset: number): BlockRef {
  const dv = new DataView(data.buffer, data.byteOffset);
  return BlockRef.of(
    BlockNumber.from(dv.getUint32(offset, true)),
    ExtIndex.from(dv.getUint16(offset + 4, true)),
  );
}

export function encodePublic(recipient: Pubkey, body: string): RemarkBytes {
  const bodyBytes = new TextEncoder().encode(body);
  const out = new Uint8Array(33 + bodyBytes.length);
  out[0] = ContentType.Public;
  out.set(recipient, 1);
  out.set(bodyBytes, 33);
  return RemarkBytes.fromBytes(out);
}

export function encodeEncrypted(
  contentType: ContentType.Encrypted | ContentType.Thread,
  viewTag: ViewTag,
  nonce: Nonce,
  ciphertext: Ciphertext,
): RemarkBytes {
  const ct = Ciphertext.asBytes(ciphertext);
  const out = new Uint8Array(14 + ct.length);
  out[0] = contentType;
  out[1] = ViewTag.get(viewTag);
  out.set(nonce, 2);
  out.set(ct, 14);
  return RemarkBytes.fromBytes(out);
}

export function encodeChannelCreate(name: ChannelName, description: ChannelDescription): RemarkBytes {
  const nb = new TextEncoder().encode(name.asString());
  const db = new TextEncoder().encode(description.asString());
  const out = new Uint8Array(3 + nb.length + db.length);
  out[0] = ContentType.ChannelCreate;
  out[1] = nb.length;
  out.set(nb, 2);
  out[2 + nb.length] = db.length;
  out.set(db, 3 + nb.length);
  return RemarkBytes.fromBytes(out);
}

export function encodeChannelMsg(
  channelRef: BlockRef,
  replyTo: BlockRef,
  continues: BlockRef,
  body: string,
): RemarkBytes {
  const bodyBytes = new TextEncoder().encode(body);
  const out = new Uint8Array(19 + bodyBytes.length);
  out[0] = ContentType.Channel;
  writeBlockRef(out, 1, channelRef);
  writeBlockRef(out, 7, replyTo);
  writeBlockRef(out, 13, continues);
  out.set(bodyBytes, 19);
  return RemarkBytes.fromBytes(out);
}

export function encodeGroup(
  nonce: Nonce,
  ephPubkey: EphPubkey,
  capsules: Capsules,
  ciphertext: Ciphertext,
): RemarkBytes {
  const caps = Capsules.asBytes(capsules);
  const ct = Ciphertext.asBytes(ciphertext);
  const out = new Uint8Array(45 + caps.length + ct.length);
  out[0] = ContentType.Group;
  out.set(nonce, 1);
  out.set(ephPubkey, 13);
  out.set(caps, 45);
  out.set(ct, 45 + caps.length);
  return RemarkBytes.fromBytes(out);
}

export function decodeRemark(remark: RemarkBytes): Remark {
  // WHY: input boundary — RemarkBytes carries an untrusted byte slice.
  const data = RemarkBytes.asBytes(remark);
  if (data.length === 0) throw new SampError("insufficient data");
  const ctByte = data[0]!;
  if ((ctByte & 0xf0) !== SAMP_VERSION) {
    throw new SampError(`unsupported version: 0x${(ctByte & 0xf0).toString(16).padStart(2, "0")}`);
  }
  switch (ctByte & 0x0f) {
    case 0x00: {
      if (data.length < 33) throw new SampError("insufficient data");
      const body = data.slice(33);
      const decoded = new TextDecoder("utf-8", { fatal: true }).decode(body);
      return {
        type: ContentType.Public,
        recipient: Pubkey.fromBytes(data.slice(1, 33)),
        body: decoded,
      };
    }
    case 0x01:
    case 0x02: {
      if (data.length < 14) throw new SampError("insufficient data");
      const viewTag = ViewTag.from(data[1]!);
      const nonce = Nonce.fromBytes(data.slice(2, 14));
      const ciphertext = Ciphertext.fromBytes(data.slice(14));
      return (ctByte & 0x0f) === 0x01
        ? { type: ContentType.Encrypted, viewTag, nonce, ciphertext }
        : { type: ContentType.Thread, viewTag, nonce, ciphertext };
    }
    case 0x03: {
      const { name, description } = decodeChannelCreatePayload(data.subarray(1));
      return {
        type: ContentType.ChannelCreate,
        name: ChannelName.parse(name),
        description: ChannelDescription.parse(description),
      };
    }
    case 0x04: {
      if (data.length < 19) throw new SampError("insufficient data");
      const body = new TextDecoder("utf-8", { fatal: true }).decode(data.slice(19));
      return {
        type: ContentType.Channel,
        channelRef: readBlockRef(data, 1),
        replyTo: readBlockRef(data, 7),
        continues: readBlockRef(data, 13),
        body,
      };
    }
    case 0x05: {
      if (data.length < 13) throw new SampError("insufficient data");
      return {
        type: ContentType.Group,
        nonce: Nonce.fromBytes(data.slice(1, 13)),
        content: data.slice(13),
      };
    }
    case 0x06:
    case 0x07:
      throw new SampError(`reserved content type: 0x${ctByte.toString(16)}`);
    default:
      return {
        type: ContentType.Application,
        tag: ctByte,
        payload: data.slice(1),
      };
  }
}

function decodeChannelCreatePayload(data: Uint8Array): { name: string; description: string } {
  if (data.length < 2) throw new SampError("insufficient data");
  const nameLen = data[0]!;
  if (nameLen === 0 || nameLen > CHANNEL_NAME_MAX) {
    throw new SampError(`channel name must be 1-${CHANNEL_NAME_MAX} bytes`);
  }
  if (data.length < 1 + nameLen + 1) throw new SampError("insufficient data");
  const name = new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(1, 1 + nameLen));
  const descOff = 1 + nameLen;
  const descLen = data[descOff]!;
  if (descLen > CHANNEL_DESC_MAX) {
    throw new SampError(`channel description must be 0-${CHANNEL_DESC_MAX} bytes`);
  }
  if (data.length < descOff + 1 + descLen) throw new SampError("insufficient data");
  const description = new TextDecoder("utf-8", { fatal: true }).decode(
    data.subarray(descOff + 1, descOff + 1 + descLen),
  );
  return { name, description };
}

export function encodeThreadContent(
  thread: BlockRef,
  replyTo: BlockRef,
  continues: BlockRef,
  body: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(THREAD_HEADER_SIZE + body.length);
  writeBlockRef(out, 0, thread);
  writeBlockRef(out, 6, replyTo);
  writeBlockRef(out, 12, continues);
  out.set(body, 18);
  return out;
}

export function decodeThreadContent(
  content: Uint8Array,
): { thread: BlockRef; replyTo: BlockRef; continues: BlockRef; body: Uint8Array } {
  if (content.length < THREAD_HEADER_SIZE) throw new SampError("insufficient data");
  return {
    thread: readBlockRef(content, 0),
    replyTo: readBlockRef(content, 6),
    continues: readBlockRef(content, 12),
    body: content.slice(18),
  };
}

export function encodeChannelContent(
  replyTo: BlockRef,
  continues: BlockRef,
  body: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(CHANNEL_HEADER_SIZE + body.length);
  writeBlockRef(out, 0, replyTo);
  writeBlockRef(out, 6, continues);
  out.set(body, 12);
  return out;
}

export function decodeChannelContent(
  content: Uint8Array,
): { replyTo: BlockRef; continues: BlockRef; body: Uint8Array } {
  if (content.length < CHANNEL_HEADER_SIZE) throw new SampError("insufficient data");
  return {
    replyTo: readBlockRef(content, 0),
    continues: readBlockRef(content, 6),
    body: content.slice(12),
  };
}

export function decodeGroupContent(
  content: Uint8Array,
): { groupRef: BlockRef; replyTo: BlockRef; continues: BlockRef; body: Uint8Array } {
  if (content.length < THREAD_HEADER_SIZE) throw new SampError("insufficient data");
  return {
    groupRef: readBlockRef(content, 0),
    replyTo: readBlockRef(content, 6),
    continues: readBlockRef(content, 12),
    body: content.slice(18),
  };
}

export function encodeGroupMembers(memberPubkeys: Pubkey[]): Uint8Array {
  const out = new Uint8Array(1 + memberPubkeys.length * 32);
  out[0] = memberPubkeys.length;
  for (let i = 0; i < memberPubkeys.length; i++) {
    out.set(memberPubkeys[i]!, 1 + i * 32);
  }
  return out;
}

export function decodeGroupMembers(data: Uint8Array): { members: Pubkey[]; body: Uint8Array } {
  if (data.length < 1) throw new SampError("insufficient data");
  const count = data[0]!;
  const end = 1 + count * 32;
  if (data.length < end) throw new SampError("insufficient data");
  const members: Pubkey[] = [];
  for (let i = 0; i < count; i++) {
    members.push(Pubkey.fromBytes(data.slice(1 + i * 32, 1 + (i + 1) * 32)));
  }
  return { members, body: data.slice(end) };
}
