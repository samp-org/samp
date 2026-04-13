package samp

import (
	"golang.org/x/crypto/blake2b"
)

const ss58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func ss58Encode(pubkey Pubkey, prefix Ss58Prefix) Ss58Address {
	payload := make([]byte, 0, 35)
	payload = append(payload, byte(prefix.v))
	payload = append(payload, pubkey.b[:]...)
	h, _ := blake2b.New512(nil)
	h.Write([]byte("SS58PRE"))
	h.Write(payload)
	sum := h.Sum(nil)
	payload = append(payload, sum[:2]...)
	return Ss58Address{address: bs58Encode(payload), pubkey: pubkey, prefix: prefix}
}

func ss58Decode(s string) (Ss58Address, error) {
	decoded, ok := bs58Decode(s)
	if !ok {
		return Ss58Address{}, ErrSs58InvalidBase58
	}
	if len(decoded) < 35 {
		return Ss58Address{}, ErrSs58TooShort
	}
	if decoded[0] >= 64 {
		return Ss58Address{}, ErrSs58PrefixUnsupported
	}
	pubkeyEnd := 1 + 32
	if len(decoded) < pubkeyEnd+2 {
		return Ss58Address{}, ErrSs58TooShort
	}
	payload := decoded[:pubkeyEnd]
	expected := decoded[pubkeyEnd : pubkeyEnd+2]
	h, _ := blake2b.New512(nil)
	h.Write([]byte("SS58PRE"))
	h.Write(payload)
	sum := h.Sum(nil)
	if sum[0] != expected[0] || sum[1] != expected[1] {
		return Ss58Address{}, ErrSs58BadChecksum
	}
	var pk [32]byte
	copy(pk[:], decoded[1:pubkeyEnd])
	prefix, err := Ss58PrefixNew(uint16(decoded[0]))
	if err != nil {
		return Ss58Address{}, err
	}
	return Ss58Address{address: s, pubkey: Pubkey{pk}, prefix: prefix}, nil
}

func bs58Decode(input string) ([]byte, bool) {
	bytes := []byte{0}
	for _, c := range input {
		if c > 127 {
			return nil, false
		}
		idx := -1
		for i := 0; i < len(ss58Alphabet); i++ {
			if ss58Alphabet[i] == byte(c) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, false
		}
		carry := idx
		for i := range bytes {
			carry += int(bytes[i]) * 58
			bytes[i] = byte(carry % 256)
			carry /= 256
		}
		for carry > 0 {
			bytes = append(bytes, byte(carry%256))
			carry /= 256
		}
	}
	for _, c := range input {
		if c == '1' {
			bytes = append(bytes, 0)
		} else {
			break
		}
	}
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes, true
}

func bs58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	digits := []uint32{0}
	for _, b := range data {
		carry := uint32(b)
		for i := range digits {
			carry += digits[i] * 256
			digits[i] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, carry%58)
			carry /= 58
		}
	}
	var out []byte
	for _, b := range data {
		if b == 0 {
			out = append(out, ss58Alphabet[0])
		} else {
			break
		}
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out = append(out, ss58Alphabet[digits[i]])
	}
	return string(out)
}
