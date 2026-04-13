pub fn decode_compact(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let mode = data[0] & 0b11;
    match mode {
        0b00 => Some((u64::from(data[0] >> 2), 1)),
        0b01 => {
            if data.len() < 2 {
                return None;
            }
            let raw = u16::from_le_bytes([data[0], data[1]]);
            Some((u64::from(raw >> 2), 2))
        }
        0b10 => {
            if data.len() < 4 {
                return None;
            }
            let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            Some((u64::from(raw >> 2), 4))
        }
        _ => {
            let bytes_following = usize::from(data[0] >> 2) + 4;
            if data.len() < 1 + bytes_following {
                return None;
            }
            let mut buf = [0u8; 8];
            let copy_len = bytes_following.min(8);
            buf[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
            Some((u64::from_le_bytes(buf), 1 + bytes_following))
        }
    }
}

pub fn encode_compact(value: u64, out: &mut Vec<u8>) {
    if value < 64 {
        out.push((value as u8) << 2);
    } else if value < 16_384 {
        let v = ((value as u16) << 2) | 0b01;
        out.extend_from_slice(&v.to_le_bytes());
    } else if value < 1 << 30 {
        let v = ((value as u32) << 2) | 0b10;
        out.extend_from_slice(&v.to_le_bytes());
    } else {
        let mut bytes = value.to_le_bytes().to_vec();
        while bytes.len() > 4 && *bytes.last().unwrap() == 0 {
            bytes.pop();
        }
        let n = bytes.len();
        let prefix = (((n - 4) as u8) << 2) | 0b11;
        out.push(prefix);
        out.extend_from_slice(&bytes);
    }
}

pub fn decode_bytes(data: &[u8]) -> Option<(&[u8], usize)> {
    let (len, prefix_len) = decode_compact(data)?;
    let len = usize::try_from(len).ok()?;
    let end = prefix_len.checked_add(len)?;
    if data.len() < end {
        return None;
    }
    Some((&data[prefix_len..end], end))
}
