package samp

import (
	"encoding/binary"
)

func DecodeCompact(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrInsufficientData
	}
	mode := data[0] & 0b11
	switch mode {
	case 0b00:
		return uint64(data[0] >> 2), 1, nil
	case 0b01:
		if len(data) < 2 {
			return 0, 0, ErrInsufficientData
		}
		raw := binary.LittleEndian.Uint16(data[:2])
		return uint64(raw >> 2), 2, nil
	case 0b10:
		if len(data) < 4 {
			return 0, 0, ErrInsufficientData
		}
		raw := binary.LittleEndian.Uint32(data[:4])
		return uint64(raw >> 2), 4, nil
	default:
		bytesFollowing := int(data[0]>>2) + 4
		if len(data) < 1+bytesFollowing {
			return 0, 0, ErrInsufficientData
		}
		var buf [8]byte
		copyLen := bytesFollowing
		if copyLen > 8 {
			copyLen = 8
		}
		copy(buf[:copyLen], data[1:1+copyLen])
		return binary.LittleEndian.Uint64(buf[:]), 1 + bytesFollowing, nil
	}
}

func EncodeCompact(value uint64) []byte {
	if value < 64 {
		return []byte{byte(value) << 2}
	}
	if value < 16_384 {
		v := (uint16(value) << 2) | 0b01
		out := make([]byte, 2)
		binary.LittleEndian.PutUint16(out, v)
		return out
	}
	if value < 1<<30 {
		v := (uint32(value) << 2) | 0b10
		out := make([]byte, 4)
		binary.LittleEndian.PutUint32(out, v)
		return out
	}
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], value)
	n := 8
	for n > 4 && raw[n-1] == 0 {
		n--
	}
	prefix := byte((((n - 4) << 2) | 0b11) & 0xff)
	out := make([]byte, 1+n)
	out[0] = prefix
	copy(out[1:], raw[:n])
	return out
}

func DecodeBytes(data []byte) ([]byte, int, error) {
	length, prefixLen, err := DecodeCompact(data)
	if err != nil {
		return nil, 0, err
	}
	end := prefixLen + int(length)
	if end < prefixLen || len(data) < end {
		return nil, 0, ErrInsufficientData
	}
	return data[prefixLen:end], end, nil
}
