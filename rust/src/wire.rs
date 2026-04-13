use crate::error::SampError;
use crate::types::{
    BlockNumber, BlockRef, Capsules, ChannelDescription, ChannelName, Ciphertext, EphPubkey,
    ExtIndex, Nonce, Pubkey, RemarkBytes, ViewTag,
};

pub const SAMP_VERSION: u8 = 0x10;

pub const CHANNEL_NAME_MAX: usize = 32;
pub const CHANNEL_DESC_MAX: usize = 128;
pub const CAPSULE_SIZE: usize = 33;

pub fn is_samp_remark(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes[0] & 0xF0 == SAMP_VERSION
}

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
    out.extend_from_slice(&r.block().get().to_le_bytes());
    out.extend_from_slice(&r.index().get().to_le_bytes());
}

fn decode_block_ref(data: &[u8], offset: usize) -> BlockRef {
    let block = BlockNumber::new(u32::from_le_bytes(
        data[offset..offset + 4].try_into().unwrap(),
    ));
    let index = ExtIndex::new(u16::from_le_bytes(
        data[offset + 4..offset + 6].try_into().unwrap(),
    ));
    BlockRef::new(block, index)
}

#[derive(Debug, Clone)]
pub enum Remark {
    Public {
        recipient: Pubkey,
        body: String,
    },
    Encrypted {
        view_tag: ViewTag,
        nonce: Nonce,
        ciphertext: Ciphertext,
    },
    Thread {
        view_tag: ViewTag,
        nonce: Nonce,
        ciphertext: Ciphertext,
    },
    ChannelCreate {
        name: ChannelName,
        description: ChannelDescription,
    },
    Channel {
        channel_ref: BlockRef,
        reply_to: BlockRef,
        continues: BlockRef,
        body: String,
    },
    Group {
        nonce: Nonce,
        content: Vec<u8>,
    },
    Application {
        tag: u8,
        payload: Vec<u8>,
    },
}

impl Remark {
    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Public { .. } => ContentType::Public,
            Self::Encrypted { .. } => ContentType::Encrypted,
            Self::Thread { .. } => ContentType::Thread,
            Self::ChannelCreate { .. } => ContentType::ChannelCreate,
            Self::Channel { .. } => ContentType::Channel,
            Self::Group { .. } => ContentType::Group,
            Self::Application { tag, .. } => ContentType::Application(*tag),
        }
    }
}

pub fn encode_public(recipient: &Pubkey, body: &str) -> RemarkBytes {
    let body_bytes = body.as_bytes();
    let mut out = Vec::with_capacity(33 + body_bytes.len());
    out.push(ContentType::Public.to_byte());
    out.extend_from_slice(recipient.as_bytes());
    out.extend_from_slice(body_bytes);
    RemarkBytes::from_bytes(out)
}

pub fn encode_encrypted(
    content_type: ContentType,
    view_tag: ViewTag,
    nonce: &Nonce,
    ciphertext: &Ciphertext,
) -> RemarkBytes {
    let mut out = Vec::with_capacity(14 + ciphertext.len());
    out.push(content_type.to_byte());
    out.push(view_tag.get());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(ciphertext.as_bytes());
    RemarkBytes::from_bytes(out)
}

pub fn encode_channel_create(name: &ChannelName, description: &ChannelDescription) -> RemarkBytes {
    let mut out = Vec::with_capacity(3 + name.len() + description.len());
    out.push(ContentType::ChannelCreate.to_byte());
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_str().as_bytes());
    out.push(description.len() as u8);
    out.extend_from_slice(description.as_str().as_bytes());
    RemarkBytes::from_bytes(out)
}

pub fn encode_channel_msg(
    channel_ref: BlockRef,
    reply_to: BlockRef,
    continues: BlockRef,
    body: &str,
) -> RemarkBytes {
    let body_bytes = body.as_bytes();
    let mut out = Vec::with_capacity(19 + body_bytes.len());
    out.push(ContentType::Channel.to_byte());
    encode_block_ref(&mut out, &channel_ref);
    encode_block_ref(&mut out, &reply_to);
    encode_block_ref(&mut out, &continues);
    out.extend_from_slice(body_bytes);
    RemarkBytes::from_bytes(out)
}

pub fn encode_group(
    nonce: &Nonce,
    eph_pubkey: &EphPubkey,
    capsules: &Capsules,
    ciphertext: &Ciphertext,
) -> RemarkBytes {
    let mut out = Vec::with_capacity(45 + capsules.as_bytes().len() + ciphertext.len());
    out.push(ContentType::Group.to_byte());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(eph_pubkey.as_bytes());
    out.extend_from_slice(capsules.as_bytes());
    out.extend_from_slice(ciphertext.as_bytes());
    RemarkBytes::from_bytes(out)
}

pub fn decode_remark(remark: &RemarkBytes) -> Result<Remark, SampError> {
    let data = remark.as_bytes();
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
            let mut recipient_bytes = [0u8; 32];
            recipient_bytes.copy_from_slice(&data[1..33]);
            let body = std::str::from_utf8(&data[33..])
                .map_err(|_| SampError::InvalidUtf8)?
                .to_string();
            Ok(Remark::Public {
                recipient: Pubkey::from_bytes(recipient_bytes),
                body,
            })
        }
        0x01 | 0x02 => {
            if data.len() < 14 {
                return Err(SampError::InsufficientData);
            }
            let view_tag = ViewTag::new(data[1]);
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&data[2..14]);
            let nonce = Nonce::from_bytes(nonce_bytes);
            let ciphertext = Ciphertext::from_bytes(data[14..].to_vec());
            if ct_byte & 0x0F == 0x01 {
                Ok(Remark::Encrypted {
                    view_tag,
                    nonce,
                    ciphertext,
                })
            } else {
                Ok(Remark::Thread {
                    view_tag,
                    nonce,
                    ciphertext,
                })
            }
        }
        0x03 => {
            let (name, description) = decode_channel_create(&data[1..])?;
            Ok(Remark::ChannelCreate {
                name: ChannelName::parse(name.to_string())?,
                description: ChannelDescription::parse(description.to_string())?,
            })
        }
        0x04 => {
            if data.len() < 19 {
                return Err(SampError::InsufficientData);
            }
            let channel_ref = decode_block_ref(data, 1);
            let reply_to = decode_block_ref(data, 7);
            let continues = decode_block_ref(data, 13);
            let body = std::str::from_utf8(&data[19..])
                .map_err(|_| SampError::InvalidUtf8)?
                .to_string();
            Ok(Remark::Channel {
                channel_ref,
                reply_to,
                continues,
                body,
            })
        }
        0x05 => {
            if data.len() < 13 {
                return Err(SampError::InsufficientData);
            }
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&data[1..13]);
            Ok(Remark::Group {
                nonce: Nonce::from_bytes(nonce_bytes),
                content: data[13..].to_vec(),
            })
        }
        0x06 | 0x07 => Err(SampError::ReservedContentType(ct_byte)),
        0x08..=0x0F => Ok(Remark::Application {
            tag: ct_byte,
            payload: data[1..].to_vec(),
        }),
        _ => unreachable!(),
    }
}

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
