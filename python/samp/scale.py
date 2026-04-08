from __future__ import annotations


def decode_compact(data: bytes) -> tuple[int, int] | None:
    if not data:
        return None
    mode = data[0] & 0b11
    if mode == 0b00:
        return data[0] >> 2, 1
    if mode == 0b01:
        if len(data) < 2:
            return None
        raw = int.from_bytes(data[:2], "little")
        return raw >> 2, 2
    if mode == 0b10:
        if len(data) < 4:
            return None
        raw = int.from_bytes(data[:4], "little")
        return raw >> 2, 4
    bytes_following = (data[0] >> 2) + 4
    if len(data) < 1 + bytes_following:
        return None
    return int.from_bytes(data[1 : 1 + bytes_following], "little"), 1 + bytes_following


def encode_compact(value: int) -> bytes:
    if value < 0:
        raise ValueError("compact integers are unsigned")
    if value < 64:
        return bytes([value << 2])
    if value < 16_384:
        return ((value << 2) | 0b01).to_bytes(2, "little")
    if value < 1 << 30:
        return ((value << 2) | 0b10).to_bytes(4, "little")
    raw = value.to_bytes(8, "little")
    while len(raw) > 4 and raw[-1] == 0:
        raw = raw[:-1]
    n = len(raw)
    prefix = (((n - 4) << 2) | 0b11).to_bytes(1, "little")
    return prefix + raw


def decode_bytes(data: bytes) -> tuple[bytes, int] | None:
    decoded = decode_compact(data)
    if decoded is None:
        return None
    length, prefix_len = decoded
    end = prefix_len + length
    if len(data) < end:
        return None
    return data[prefix_len:end], end
