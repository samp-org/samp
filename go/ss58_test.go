package samp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var testPubkey = PubkeyFromBytes([32]byte{
	0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd,
	0x04, 0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3,
	0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d,
})

func TestSs58EncodeDecodeRoundTrip(t *testing.T) {
	addr := Ss58AddressEncode(testPubkey, Ss58SubstrateGeneric)
	parsed, err := Ss58AddressParse(addr.String())
	require.NoError(t, err)
	require.Equal(t, addr.String(), parsed.String())
	require.Equal(t, testPubkey.Bytes(), parsed.Pubkey().Bytes())
	require.Equal(t, uint16(42), parsed.Prefix().Get())
}

func TestSs58EncodeDecodePrefix0(t *testing.T) {
	addr := Ss58AddressEncode(testPubkey, Ss58Polkadot)
	parsed, err := Ss58AddressParse(addr.String())
	require.NoError(t, err)
	require.Equal(t, addr.String(), parsed.String())
	require.Equal(t, testPubkey.Bytes(), parsed.Pubkey().Bytes())
	require.Equal(t, uint16(0), parsed.Prefix().Get())
}

func TestSs58DecodeBadChecksum(t *testing.T) {
	addr := Ss58AddressEncode(testPubkey, Ss58SubstrateGeneric)
	s := addr.String()
	lastChar := s[len(s)-1]
	var replacement byte = 'A'
	if lastChar == 'A' {
		replacement = 'B'
	}
	corrupted := s[:len(s)-1] + string(replacement)
	_, err := Ss58AddressParse(corrupted)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSs58BadChecksum)
}

func TestSs58DecodeTooShort(t *testing.T) {
	_, err := Ss58AddressParse("abc")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSs58TooShort)
}

func TestSs58DecodeEmpty(t *testing.T) {
	_, err := Ss58AddressParse("")
	require.Error(t, err)
}

func TestSs58PrefixBoundary(t *testing.T) {
	prefix63, err := Ss58PrefixNew(63)
	require.NoError(t, err)
	addr := Ss58AddressEncode(testPubkey, prefix63)
	parsed, err := Ss58AddressParse(addr.String())
	require.NoError(t, err)
	require.Equal(t, uint16(63), parsed.Prefix().Get())

	_, err = Ss58PrefixNew(64)
	require.Error(t, err)
}
