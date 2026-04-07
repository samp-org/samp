use crate::error::SampError;

pub const SAMP_VERSION: u8 = 0x10;

pub const CONTENT_TYPE_PUBLIC: u8 = 0x10;
pub const CONTENT_TYPE_ENCRYPTED: u8 = 0x11;
pub const CONTENT_TYPE_THREAD: u8 = 0x12;
pub const CONTENT_TYPE_CHANNEL_CREATE: u8 = 0x13;
pub const CONTENT_TYPE_CHANNEL: u8 = 0x14;
pub const CONTENT_TYPE_GROUP: u8 = 0x15;

pub const CHANNEL_NAME_MAX: usize = 32;
pub const CHANNEL_DESC_MAX: usize = 128;
pub const CAPSULE_SIZE: usize = 33;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    Public,
    Encrypted,
    Thread,
    ChannelCreate,
    Channel,
    Group,
    Application(u8),
}

impl ContentType {
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::Public => CONTENT_TYPE_PUBLIC,
            Self::Encrypted => CONTENT_TYPE_ENCRYPTED,
            Self::Thread => CONTENT_TYPE_THREAD,
            Self::ChannelCreate => CONTENT_TYPE_CHANNEL_CREATE,
            Self::Channel => CONTENT_TYPE_CHANNEL,
            Self::Group => CONTENT_TYPE_GROUP,
            Self::Application(b) => *b,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self, SampError> {
        if b & 0xF0 != SAMP_VERSION {
            return Err(SampError::InvalidVersion(b & 0xF0));
        }
        match b & 0x0F {
            0x00 => Ok(Self::Public),
            0x01 => Ok(Self::Encrypted),
            0x02 => Ok(Self::Thread),
            0x03 => Ok(Self::ChannelCreate),
            0x04 => Ok(Self::Channel),
            0x05 => Ok(Self::Group),
            0x06 | 0x07 => Err(SampError::ReservedContentType(b)),
            0x08..=0x0F => Ok(Self::Application(b)),
            _ => unreachable!(),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted | Self::Thread | Self::Group)
    }
}

/// A reference to a specific extrinsic on a finalized Substrate block.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct BlockRef {
    pub block: u32,
    pub index: u16,
}

impl BlockRef {
    pub const ZERO: Self = Self { block: 0, index: 0 };

    pub fn is_zero(&self) -> bool {
        self.block == 0 && self.index == 0
    }
}

fn encode_block_ref(out: &mut Vec<u8>, r: &BlockRef) {
    out.extend_from_slice(&r.block.to_le_bytes());
    out.extend_from_slice(&r.index.to_le_bytes());
}

fn decode_block_ref(data: &[u8], offset: usize) -> BlockRef {
    BlockRef {
        block: u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()),
        index: u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap()),
    }
}

/// Parsed SAMP remark. Sender and timestamp come from extrinsic context.
#[derive(Debug, Clone)]
pub struct Remark {
    pub content_type: ContentType,
    /// For Public: recipient pubkey. For Channel: channel BlockRef in first 6 bytes.
    pub recipient: [u8; 32],
    pub view_tag: u8,
    pub nonce: [u8; 12],
    pub content: Vec<u8>,
}

/// Encode a public message: 0x10 || recipient(32) || body.
pub fn encode_public(recipient: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33 + body.len());
    out.push(CONTENT_TYPE_PUBLIC);
    out.extend_from_slice(recipient);
    out.extend_from_slice(body);
    out
}

/// Encode an encrypted remark (0x11 or 0x12):
/// content_type(1) || view_tag(1) || nonce(12) || encrypted_content(var).
pub fn encode_encrypted(
    content_type: u8,
    view_tag: u8,
    nonce: &[u8; 12],
    encrypted_content: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + encrypted_content.len());
    out.push(content_type);
    out.push(view_tag);
    out.extend_from_slice(nonce);
    out.extend_from_slice(encrypted_content);
    out
}

/// Encode a channel creation: 0x13 || name_len(1) || name || desc_len(1) || desc.
pub fn encode_channel_create(name: &str, description: &str) -> Result<Vec<u8>, SampError> {
    if name.is_empty() || name.len() > CHANNEL_NAME_MAX {
        return Err(SampError::InvalidChannelName);
    }
    if description.len() > CHANNEL_DESC_MAX {
        return Err(SampError::InvalidChannelDesc);
    }
    let mut out = Vec::with_capacity(3 + name.len() + description.len());
    out.push(CONTENT_TYPE_CHANNEL_CREATE);
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(description.len() as u8);
    out.extend_from_slice(description.as_bytes());
    Ok(out)
}

/// Encode a channel message: 0x14 || channel_ref(6) || reply_to(6) || continues(6) || body.
pub fn encode_channel_msg(
    channel_ref: BlockRef,
    reply_to: BlockRef,
    continues: BlockRef,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(19 + body.len());
    out.push(CONTENT_TYPE_CHANNEL);
    encode_block_ref(&mut out, &channel_ref);
    encode_block_ref(&mut out, &reply_to);
    encode_block_ref(&mut out, &continues);
    out.extend_from_slice(body);
    out
}

/// Encode a group message: 0x15 || nonce(12) || eph_pubkey(32) || capsules || ciphertext.
pub fn encode_group(
    nonce: &[u8; 12],
    eph_pubkey: &[u8; 32],
    capsules: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(45 + capsules.len() + ciphertext.len());
    out.push(CONTENT_TYPE_GROUP);
    out.extend_from_slice(nonce);
    out.extend_from_slice(eph_pubkey);
    out.extend_from_slice(capsules);
    out.extend_from_slice(ciphertext);
    out
}

/// Decode a SAMP remark.
pub fn decode_remark(data: &[u8]) -> Result<Remark, SampError> {
    if data.is_empty() {
        return Err(SampError::InsufficientData);
    }
    let ct_byte = data[0];
    if ct_byte & 0xF0 != SAMP_VERSION {
        return Err(SampError::InvalidVersion(ct_byte & 0xF0));
    }

    match ct_byte & 0x0F {
        0x00 => {
            if data.len() < 33 {
                return Err(SampError::InsufficientData);
            }
            let mut recipient = [0u8; 32];
            recipient.copy_from_slice(&data[1..33]);
            let body = data[33..].to_vec();
            if std::str::from_utf8(&body).is_err() {
                return Err(SampError::InvalidUtf8);
            }
            Ok(Remark {
                content_type: ContentType::Public,
                recipient,
                view_tag: 0,
                nonce: [0; 12],
                content: body,
            })
        }
        0x01 | 0x02 => {
            if data.len() < 14 {
                return Err(SampError::InsufficientData);
            }
            let view_tag = data[1];
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&data[2..14]);
            let content = data[14..].to_vec();
            Ok(Remark {
                content_type: ContentType::from_byte(ct_byte)?,
                recipient: [0; 32],
                view_tag,
                nonce,
                content,
            })
        }
        0x03 => Ok(Remark {
            content_type: ContentType::ChannelCreate,
            recipient: [0; 32],
            view_tag: 0,
            nonce: [0; 12],
            content: data[1..].to_vec(),
        }),
        0x04 => {
            if data.len() < 19 {
                return Err(SampError::InsufficientData);
            }
            let channel_ref = decode_block_ref(data, 1);
            let mut recipient = [0u8; 32];
            recipient[0..4].copy_from_slice(&channel_ref.block.to_le_bytes());
            recipient[4..6].copy_from_slice(&channel_ref.index.to_le_bytes());
            let content = data[7..].to_vec();
            Ok(Remark {
                content_type: ContentType::Channel,
                recipient,
                view_tag: 0,
                nonce: [0; 12],
                content,
            })
        }
        0x05 => {
            if data.len() < 45 {
                return Err(SampError::InsufficientData);
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&data[1..13]);
            let content = data[13..].to_vec();
            Ok(Remark {
                content_type: ContentType::Group,
                recipient: [0; 32],
                view_tag: 0,
                nonce,
                content,
            })
        }
        _ => Err(SampError::ReservedContentType(ct_byte)),
    }
}

// ---------------------------------------------------------------------------
// Content helpers (thread/channel/group plaintext encoding)
// ---------------------------------------------------------------------------

pub const CHANNEL_HEADER_SIZE: usize = 12;
pub const THREAD_HEADER_SIZE: usize = 18;

/// Encode thread plaintext: thread(6) || reply_to(6) || continues(6) || body.
pub fn encode_thread_content(
    thread: BlockRef,
    reply_to: BlockRef,
    continues: BlockRef,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(THREAD_HEADER_SIZE + body.len());
    encode_block_ref(&mut out, &thread);
    encode_block_ref(&mut out, &reply_to);
    encode_block_ref(&mut out, &continues);
    out.extend_from_slice(body);
    out
}

/// Decode thread plaintext. Returns (thread, reply_to, continues, body).
pub fn decode_thread_content(
    content: &[u8],
) -> Result<(BlockRef, BlockRef, BlockRef, &[u8]), SampError> {
    if content.len() < THREAD_HEADER_SIZE {
        return Err(SampError::InsufficientData);
    }
    let thread = decode_block_ref(content, 0);
    let reply_to = decode_block_ref(content, 6);
    let continues = decode_block_ref(content, 12);
    Ok((thread, reply_to, continues, &content[18..]))
}

/// Encode channel plaintext: reply_to(6) || continues(6) || body.
pub fn encode_channel_content(reply_to: BlockRef, continues: BlockRef, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHANNEL_HEADER_SIZE + body.len());
    encode_block_ref(&mut out, &reply_to);
    encode_block_ref(&mut out, &continues);
    out.extend_from_slice(body);
    out
}

/// Decode channel plaintext. Returns (reply_to, continues, body).
pub fn decode_channel_content(content: &[u8]) -> Result<(BlockRef, BlockRef, &[u8]), SampError> {
    if content.len() < CHANNEL_HEADER_SIZE {
        return Err(SampError::InsufficientData);
    }
    let reply_to = decode_block_ref(content, 0);
    let continues = decode_block_ref(content, 6);
    Ok((reply_to, continues, &content[12..]))
}

/// Decode channel creation content (after content_type byte). Returns (name, description).
pub fn decode_channel_create(data: &[u8]) -> Result<(&str, &str), SampError> {
    if data.is_empty() {
        return Err(SampError::InsufficientData);
    }
    let name_len = data[0] as usize;
    if name_len == 0 || name_len > CHANNEL_NAME_MAX {
        return Err(SampError::InvalidChannelName);
    }
    if data.len() < 1 + name_len + 1 {
        return Err(SampError::InsufficientData);
    }
    let name = std::str::from_utf8(&data[1..1 + name_len]).map_err(|_| SampError::InvalidUtf8)?;
    let desc_offset = 1 + name_len;
    let desc_len = data[desc_offset] as usize;
    if desc_len > CHANNEL_DESC_MAX {
        return Err(SampError::InvalidChannelDesc);
    }
    if data.len() < desc_offset + 1 + desc_len {
        return Err(SampError::InsufficientData);
    }
    let description = std::str::from_utf8(&data[desc_offset + 1..desc_offset + 1 + desc_len])
        .map_err(|_| SampError::InvalidUtf8)?;
    Ok((name, description))
}

/// Decode group message plaintext: group_ref(6) || reply_to(6) || continues(6) || body.
pub fn decode_group_content(
    content: &[u8],
) -> Result<(BlockRef, BlockRef, BlockRef, &[u8]), SampError> {
    if content.len() < THREAD_HEADER_SIZE {
        return Err(SampError::InsufficientData);
    }
    let group_ref = decode_block_ref(content, 0);
    let reply_to = decode_block_ref(content, 6);
    let continues = decode_block_ref(content, 12);
    Ok((group_ref, reply_to, continues, &content[18..]))
}

/// Encode group member list prefix: member_count(1) || N * pubkey(32).
pub fn encode_group_members(member_pubkeys: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + member_pubkeys.len() * 32);
    out.push(member_pubkeys.len() as u8);
    for pk in member_pubkeys {
        out.extend_from_slice(pk);
    }
    out
}

/// Decode group root body: member_count(1) || pubkeys(32*N) || remaining_text.
pub fn decode_group_members(data: &[u8]) -> Result<(Vec<[u8; 32]>, &[u8]), SampError> {
    if data.is_empty() {
        return Err(SampError::InsufficientData);
    }
    let member_count = data[0] as usize;
    let members_start = 1;
    let members_end = members_start + member_count * 32;
    if data.len() < members_end {
        return Err(SampError::InsufficientData);
    }
    let mut members = Vec::with_capacity(member_count);
    for i in 0..member_count {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[members_start + i * 32..members_start + (i + 1) * 32]);
        members.push(pk);
    }
    Ok((members, &data[members_end..]))
}

/// Extract channel ref from a Remark's recipient field.
pub fn channel_ref_from_recipient(recipient: &[u8; 32]) -> BlockRef {
    let block = u32::from_le_bytes(recipient[0..4].try_into().unwrap());
    let index = u16::from_le_bytes(recipient[4..6].try_into().unwrap());
    BlockRef { block, index }
}
