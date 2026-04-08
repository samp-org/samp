use crate::error::SampError;
use crate::types::{BlockRef, Nonce, Pubkey};

pub const SAMP_VERSION: u8 = 0x10;

pub const CHANNEL_NAME_MAX: usize = 32;
pub const CHANNEL_DESC_MAX: usize = 128;
pub const CAPSULE_SIZE: usize = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Public => SAMP_VERSION,
            Self::Encrypted => SAMP_VERSION | 0x01,
            Self::Thread => SAMP_VERSION | 0x02,
            Self::ChannelCreate => SAMP_VERSION | 0x03,
            Self::Channel => SAMP_VERSION | 0x04,
            Self::Group => SAMP_VERSION | 0x05,
            Self::Application(b) => b,
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

#[derive(Debug, Clone)]
pub struct Remark {
    pub content_type: ContentType,
    pub recipient: [u8; 32],
    pub view_tag: u8,
    pub nonce: Nonce,
    pub content: Vec<u8>,
}

pub fn encode_public(recipient: &Pubkey, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33 + body.len());
    out.push(ContentType::Public.to_byte());
    out.extend_from_slice(recipient.as_bytes());
    out.extend_from_slice(body);
    out
}

pub fn encode_encrypted(
    content_type: ContentType,
    view_tag: u8,
    nonce: &Nonce,
    encrypted_content: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + encrypted_content.len());
    out.push(content_type.to_byte());
    out.push(view_tag);
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(encrypted_content);
    out
}

pub fn encode_channel_create(name: &str, description: &str) -> Result<Vec<u8>, SampError> {
    if name.is_empty() || name.len() > CHANNEL_NAME_MAX {
        return Err(SampError::InvalidChannelName);
    }
    if description.len() > CHANNEL_DESC_MAX {
        return Err(SampError::InvalidChannelDesc);
    }
    let mut out = Vec::with_capacity(3 + name.len() + description.len());
    out.push(ContentType::ChannelCreate.to_byte());
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(description.len() as u8);
    out.extend_from_slice(description.as_bytes());
    Ok(out)
}

pub fn encode_channel_msg(
    channel_ref: BlockRef,
    reply_to: BlockRef,
    continues: BlockRef,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(19 + body.len());
    out.push(ContentType::Channel.to_byte());
    encode_block_ref(&mut out, &channel_ref);
    encode_block_ref(&mut out, &reply_to);
    encode_block_ref(&mut out, &continues);
    out.extend_from_slice(body);
    out
}

pub fn encode_group(
    nonce: &Nonce,
    eph_pubkey: &Pubkey,
    capsules: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(45 + capsules.len() + ciphertext.len());
    out.push(ContentType::Group.to_byte());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(eph_pubkey.as_bytes());
    out.extend_from_slice(capsules);
    out.extend_from_slice(ciphertext);
    out
}

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
                nonce: Nonce::ZERO,
                content: body,
            })
        }
        0x01 | 0x02 => {
            if data.len() < 14 {
                return Err(SampError::InsufficientData);
            }
            let view_tag = data[1];
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&data[2..14]);
            let content = data[14..].to_vec();
            Ok(Remark {
                content_type: ContentType::from_byte(ct_byte)?,
                recipient: [0; 32],
                view_tag,
                nonce: Nonce::from_bytes(nonce_bytes),
                content,
            })
        }
        0x03 => Ok(Remark {
            content_type: ContentType::ChannelCreate,
            recipient: [0; 32],
            view_tag: 0,
            nonce: Nonce::ZERO,
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
                nonce: Nonce::ZERO,
                content,
            })
        }
        0x05 => {
            if data.len() < 45 {
                return Err(SampError::InsufficientData);
            }
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&data[1..13]);
            let content = data[13..].to_vec();
            Ok(Remark {
                content_type: ContentType::Group,
                recipient: [0; 32],
                view_tag: 0,
                nonce: Nonce::from_bytes(nonce_bytes),
                content,
            })
        }
        _ => Err(SampError::ReservedContentType(ct_byte)),
    }
}

// Content helpers (thread/channel/group plaintext encoding)

pub const CHANNEL_HEADER_SIZE: usize = 12;
pub const THREAD_HEADER_SIZE: usize = 18;

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

pub fn encode_channel_content(reply_to: BlockRef, continues: BlockRef, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHANNEL_HEADER_SIZE + body.len());
    encode_block_ref(&mut out, &reply_to);
    encode_block_ref(&mut out, &continues);
    out.extend_from_slice(body);
    out
}

pub fn decode_channel_content(content: &[u8]) -> Result<(BlockRef, BlockRef, &[u8]), SampError> {
    if content.len() < CHANNEL_HEADER_SIZE {
        return Err(SampError::InsufficientData);
    }
    let reply_to = decode_block_ref(content, 0);
    let continues = decode_block_ref(content, 6);
    Ok((reply_to, continues, &content[12..]))
}

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

pub fn encode_group_members(member_pubkeys: &[Pubkey]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + member_pubkeys.len() * 32);
    out.push(member_pubkeys.len() as u8);
    for pk in member_pubkeys {
        out.extend_from_slice(pk.as_bytes());
    }
    out
}

pub fn decode_group_members(data: &[u8]) -> Result<(Vec<Pubkey>, &[u8]), SampError> {
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
        members.push(Pubkey::from_bytes(pk));
    }
    Ok((members, &data[members_end..]))
}

pub fn channel_ref_from_recipient(recipient: &[u8; 32]) -> BlockRef {
    BlockRef {
        block: u32::from_le_bytes(recipient[0..4].try_into().unwrap()),
        index: u16::from_le_bytes(recipient[4..6].try_into().unwrap()),
    }
}
