package samp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeRemarkThreadTypeParsesCorrectly(t *testing.T) {
	data := make([]byte, 14)
	data[0] = 0x12
	data[1] = 0xAA
	r, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.NoError(t, err)
	tr, ok := r.(ThreadRemark)
	require.True(t, ok)
	require.Equal(t, byte(0xAA), tr.ViewTag.Get())
}

func TestDecodeChannelCreateDescTooLongByte(t *testing.T) {
	// Valid name "A", desc length 0xFF > 128.
	data := []byte{0x13, 0x01, 0x41, 0xFF}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInvalidChannelDesc)
}

func TestEncodeGroupRemarkLayout(t *testing.T) {
	nonce := NonceFromBytes([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	ephPub := EphPubkeyFromBytes([32]byte{0xAA})
	capsules := Capsules{b: []byte{0x01, 0x02}}
	ct := CiphertextFromBytes([]byte{0x03, 0x04})

	remark := EncodeGroup(nonce, ephPub, capsules, ct)
	b := remark.Bytes()
	require.Equal(t, byte(0x15), b[0])
	require.Equal(t, 1+12+32+2+2, len(b))
}

func TestDecodeChannelCreateNameTooLongByte(t *testing.T) {
	// Name length 0x21 = 33 > 32.
	data := []byte{0x13, 0x21}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.Error(t, err)
}
