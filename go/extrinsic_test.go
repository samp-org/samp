package samp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type extrinsicChainParamsCase struct {
	GenesisHash string `json:"genesis_hash"`
	SpecVersion uint32 `json:"spec_version"`
	TxVersion   uint32 `json:"tx_version"`
}

type extrinsicCase struct {
	Label             string                   `json:"label"`
	PalletIdx         uint8                    `json:"pallet_idx"`
	CallIdx           uint8                    `json:"call_idx"`
	CallArgs          string                   `json:"call_args"`
	PublicKey         string                   `json:"public_key"`
	FixedSignature    string                   `json:"fixed_signature"`
	Nonce             uint32                   `json:"nonce"`
	ChainParams       extrinsicChainParamsCase `json:"chain_params"`
	ExpectedExtrinsic string                   `json:"expected_extrinsic"`
}

type extrinsicVectors struct {
	Cases []extrinsicCase `json:"cases"`
}

var alicePublicKey = mustHex32("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
var fixedSignature = func() [64]byte {
	var s [64]byte
	for i := range s {
		s[i] = 0xab
	}
	return s
}()

func mustHex32(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustHex64(s string) [64]byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	var out [64]byte
	copy(out[:], b)
	return out
}

func fixedSigner(_ []byte) ([64]byte, error) {
	return fixedSignature, nil
}

func makeChainParams() ChainParams {
	var genesis [32]byte
	for i := range genesis {
		genesis[i] = 0x11
	}
	return ChainParams{
		GenesisHash: genesis,
		SpecVersion: 100,
		TxVersion:   1,
	}
}

func buildRemarkArgs(remark []byte) []byte {
	out := EncodeCompact(uint64(len(remark)))
	return append(out, remark...)
}

func TestBuildSignedExtrinsicRoundTripsThroughExtract(t *testing.T) {
	args := buildRemarkArgs([]byte("hello bob"))
	ext, err := BuildSignedExtrinsic(0, 7, args, alicePublicKey, fixedSigner, 0, makeChainParams())
	require.NoError(t, err)

	signer, ok := ExtractSigner(ext)
	require.True(t, ok)
	require.Equal(t, alicePublicKey, signer)

	extracted, ok := ExtractCall(ext)
	require.True(t, ok)
	require.Equal(t, uint8(0), extracted.Pallet)
	require.Equal(t, uint8(7), extracted.Call)
	require.Equal(t, args, extracted.Args)
}

func TestBuildSignedExtrinsicStartsWithCompactLengthPrefix(t *testing.T) {
	args := buildRemarkArgs([]byte("x"))
	ext, err := BuildSignedExtrinsic(0, 7, args, alicePublicKey, fixedSigner, 0, makeChainParams())
	require.NoError(t, err)
	declaredLen, prefixLen, err := DecodeCompact(ext)
	require.NoError(t, err)
	require.Equal(t, len(ext), prefixLen+int(declaredLen))
}

func TestBuildSignedExtrinsicUsesImmortalEraByte(t *testing.T) {
	args := buildRemarkArgs([]byte("x"))
	ext, err := BuildSignedExtrinsic(0, 7, args, alicePublicKey, fixedSigner, 0, makeChainParams())
	require.NoError(t, err)
	_, prefixLen, err := DecodeCompact(ext)
	require.NoError(t, err)
	payload := ext[prefixLen:]
	eraOffset := 1 + 1 + 32 + 1 + 64
	require.Equal(t, byte(0x00), payload[eraOffset])
}

func TestBuildSignedExtrinsicDifferentNoncesProduceDifferentBytes(t *testing.T) {
	args := buildRemarkArgs([]byte("x"))
	cp := makeChainParams()
	a, err := BuildSignedExtrinsic(0, 7, args, alicePublicKey, fixedSigner, 0, cp)
	require.NoError(t, err)
	b, err := BuildSignedExtrinsic(0, 7, args, alicePublicKey, fixedSigner, 1, cp)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestExtractSignerReturnsFalseForUnsignedExtrinsic(t *testing.T) {
	unsigned := []byte{0x10, 0x04, 0x03, 0x00, 0x00}
	_, ok := ExtractSigner(unsigned)
	require.False(t, ok)
}

func TestExtractCallReturnsFalseForUnsignedExtrinsic(t *testing.T) {
	unsigned := []byte{0x10, 0x04, 0x03, 0x00, 0x00}
	_, ok := ExtractCall(unsigned)
	require.False(t, ok)
}

func TestExtractSignerReturnsFalseForEmptyInput(t *testing.T) {
	_, ok := ExtractSigner([]byte{})
	require.False(t, ok)
}

func TestBuildSignedExtrinsicPayloadAbove256BytesUsesBlake2Hash(t *testing.T) {
	bigRemark := make([]byte, 1024)
	for i := range bigRemark {
		bigRemark[i] = 0xab
	}
	args := buildRemarkArgs(bigRemark)
	var captured []int
	capturingSigner := func(msg []byte) ([64]byte, error) {
		captured = append(captured, len(msg))
		return fixedSignature, nil
	}
	ext, err := BuildSignedExtrinsic(0, 7, args, alicePublicKey, capturingSigner, 0, makeChainParams())
	require.NoError(t, err)
	require.Equal(t, []int{32}, captured)
	extracted, ok := ExtractCall(ext)
	require.True(t, ok)
	require.Equal(t, args, extracted.Args)
}

func TestSigningClosureErrorPropagates(t *testing.T) {
	failingSigner := func(_ []byte) ([64]byte, error) {
		return [64]byte{}, errors.New("hardware wallet disconnected")
	}
	_, err := BuildSignedExtrinsic(0, 7, []byte{}, alicePublicKey, failingSigner, 0, makeChainParams())
	require.ErrorContains(t, err, "hardware wallet disconnected")
}

func TestMatchesE2EExtrinsicVectorsFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "e2e", "extrinsic-vectors.json"))
	require.NoError(t, err)

	var vectors extrinsicVectors
	require.NoError(t, json.Unmarshal(raw, &vectors))

	for _, c := range vectors.Cases {
		publicKey := mustHex32(stripHex(c.PublicKey))
		signature := mustHex64(stripHex(c.FixedSignature))
		callArgs := unhexBytes(t, c.CallArgs)
		genesis := mustHex32(stripHex(c.ChainParams.GenesisHash))
		chain := ChainParams{
			GenesisHash: genesis,
			SpecVersion: c.ChainParams.SpecVersion,
			TxVersion:   c.ChainParams.TxVersion,
		}

		signer := func(_ []byte) ([64]byte, error) {
			return signature, nil
		}

		built, err := BuildSignedExtrinsic(c.PalletIdx, c.CallIdx, callArgs, publicKey, signer, c.Nonce, chain)
		require.NoError(t, err)
		require.Equal(t, unhexBytes(t, c.ExpectedExtrinsic), built, "case %s", c.Label)
	}
}

func stripHex(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}
