package samp

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

type scaleCompactCase struct {
	Value    string `json:"value"`
	Encoded  string `json:"encoded"`
	Consumed int    `json:"consumed"`
}

type scaleVectors struct {
	Compact []scaleCompactCase `json:"compact"`
}

func unhexBytes(t *testing.T, s string) []byte {
	t.Helper()
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestCompactModeZeroLowerBound(t *testing.T) {
	require.Equal(t, []byte{0x00}, EncodeCompact(0))
	v, n, err := DecodeCompact([]byte{0x00})
	require.NoError(t, err)
	require.Equal(t, uint64(0), v)
	require.Equal(t, 1, n)
}

func TestCompactModeZeroUpperBound(t *testing.T) {
	require.Equal(t, []byte{0xfc}, EncodeCompact(63))
	v, n, err := DecodeCompact([]byte{0xfc})
	require.NoError(t, err)
	require.Equal(t, uint64(63), v)
	require.Equal(t, 1, n)
}

func TestCompactModeOneLowerBound(t *testing.T) {
	require.Equal(t, []byte{0x01, 0x01}, EncodeCompact(64))
	v, n, err := DecodeCompact([]byte{0x01, 0x01})
	require.NoError(t, err)
	require.Equal(t, uint64(64), v)
	require.Equal(t, 2, n)
}

func TestCompactModeOneUpperBound(t *testing.T) {
	enc := EncodeCompact(16383)
	v, n, err := DecodeCompact(enc)
	require.NoError(t, err)
	require.Equal(t, uint64(16383), v)
	require.Equal(t, 2, n)
}

func TestCompactModeTwoLowerBound(t *testing.T) {
	enc := EncodeCompact(16384)
	v, n, err := DecodeCompact(enc)
	require.NoError(t, err)
	require.Equal(t, uint64(16384), v)
	require.Equal(t, 4, n)
}

func TestCompactModeTwoUpperBound(t *testing.T) {
	enc := EncodeCompact(1<<30 - 1)
	v, n, err := DecodeCompact(enc)
	require.NoError(t, err)
	require.Equal(t, uint64(1<<30-1), v)
	require.Equal(t, 4, n)
}

func TestCompactBigIntMode2Pow30(t *testing.T) {
	v, _, err := DecodeCompact(EncodeCompact(1 << 30))
	require.NoError(t, err)
	require.Equal(t, uint64(1<<30), v)
}

func TestCompactBigIntModeU64Max(t *testing.T) {
	v, _, err := DecodeCompact(EncodeCompact(math.MaxUint64))
	require.NoError(t, err)
	require.Equal(t, uint64(math.MaxUint64), v)
}

func TestCompactRoundTripAcrossAllModes(t *testing.T) {
	probes := []uint64{0, 1, 63, 64, 100, 16383, 16384, 1 << 20, (1 << 30) - 1, 1 << 30, 1 << 32, math.MaxUint64}
	for _, value := range probes {
		decoded, _, err := DecodeCompact(EncodeCompact(value))
		require.NoError(t, err)
		require.Equal(t, value, decoded)
	}
}

func TestDecodeCompactReturnsErrorOnEmptyInput(t *testing.T) {
	_, _, err := DecodeCompact([]byte{})
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeCompactReturnsErrorOnTruncatedTwoByteMode(t *testing.T) {
	_, _, err := DecodeCompact([]byte{0x01})
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeCompactReturnsErrorOnTruncatedFourByteMode(t *testing.T) {
	_, _, err := DecodeCompact([]byte{0x02, 0x00, 0x00})
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeCompactReturnsErrorOnTruncatedBigIntMode(t *testing.T) {
	_, _, err := DecodeCompact([]byte{0x03, 0x01})
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeBytesExtractsPayloadAfterCompactLength(t *testing.T) {
	wire := append(EncodeCompact(5), []byte("hello")...)
	payload, consumed, err := DecodeBytes(wire)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), payload)
	require.Equal(t, 6, consumed)
}

func TestDecodeBytesReturnsErrorWhenPayloadTruncated(t *testing.T) {
	wire := append(EncodeCompact(10), []byte("only5")...)
	_, _, err := DecodeBytes(wire)
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeCompactBigIntModeTruncatedPayload(t *testing.T) {
	// BigInt mode: low 2 bits = 0b11, upper 6 bits encode (n-4) where n is byte count.
	// 0x13 = 0b00010011 -> mode=0b11, n = (0x13>>2)+4 = 4+4 = 8 bytes follow.
	// But we only provide 3 bytes after the prefix.
	_, _, err := DecodeCompact([]byte{0x13, 0x01, 0x02, 0x03})
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeBytesCompactOverflow(t *testing.T) {
	// Compact length that would overflow int when computing end offset.
	// A compact-encoded very large value. We use BigInt mode with n=8 (max).
	// 0x13 means 8 bytes follow. Set them to large values.
	data := []byte{0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}
	_, _, err := DecodeBytes(data)
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeBytesForwardDecodeCompactError(t *testing.T) {
	// Empty input should forward the DecodeCompact error.
	_, _, err := DecodeBytes([]byte{})
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestMatchesE2EScaleVectorsFixture(t *testing.T) {
	path := filepath.Join("..", "e2e", "scale-vectors.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var vectors scaleVectors
	require.NoError(t, json.Unmarshal(raw, &vectors))

	for _, c := range vectors.Compact {
		value, err := strconv.ParseUint(c.Value, 10, 64)
		require.NoError(t, err)

		expected := unhexBytes(t, c.Encoded)
		require.Equal(t, expected, EncodeCompact(value))

		decoded, consumed, err := DecodeCompact(expected)
		require.NoError(t, err)
		require.Equal(t, value, decoded)
		require.Equal(t, c.Consumed, consumed)
	}
}
