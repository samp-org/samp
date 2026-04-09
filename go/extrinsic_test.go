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

var alicePublicKey = PubkeyFromBytes(mustHex32("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"))
var fixedSignature = func() Signature {
	var s [64]byte
	for i := range s {
		s[i] = 0xab
	}
	return SignatureFromBytes(s)
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

func fixedSigner(_ []byte) (Signature, error) {
	return fixedSignature, nil
}

func makeChainParams() ChainParams {
	var genesis [32]byte
	for i := range genesis {
		genesis[i] = 0x11
	}
	return ChainParams{
		GenesisHash: GenesisHashFromBytes(genesis),
		SpecVersion: SpecVersionFrom(100),
		TxVersion:   TxVersionFrom(1),
	}
}

func buildRemarkArgs(remark []byte) CallArgs {
	out := EncodeCompact(uint64(len(remark)))
	return CallArgsFromBytes(append(out, remark...))
}

func TestBuildSignedExtrinsicRoundTripsThroughExtract(t *testing.T) {
	args := buildRemarkArgs([]byte("hello bob"))
	ext, err := BuildSignedExtrinsic(PalletIdxFrom(0), CallIdxFrom(7), args, alicePublicKey, fixedSigner, ExtrinsicNonceFrom(0), makeChainParams())
	require.NoError(t, err)

	signer, ok := ExtractSigner(ext)
	require.True(t, ok)
	require.Equal(t, alicePublicKey, signer)

	extracted, ok := ExtractCall(ext)
	require.True(t, ok)
	require.Equal(t, uint8(0), extracted.Pallet.Get())
	require.Equal(t, uint8(7), extracted.Call.Get())
	require.Equal(t, args.Bytes(), extracted.Args.Bytes())
}

func TestBuildSignedExtrinsicStartsWithCompactLengthPrefix(t *testing.T) {
	args := buildRemarkArgs([]byte("x"))
	ext, err := BuildSignedExtrinsic(PalletIdxFrom(0), CallIdxFrom(7), args, alicePublicKey, fixedSigner, ExtrinsicNonceFrom(0), makeChainParams())
	require.NoError(t, err)
	declaredLen, prefixLen, err := DecodeCompact(ext.Bytes())
	require.NoError(t, err)
	require.Equal(t, ext.Len(), prefixLen+int(declaredLen))
}

func TestBuildSignedExtrinsicUsesImmortalEraByte(t *testing.T) {
	args := buildRemarkArgs([]byte("x"))
	ext, err := BuildSignedExtrinsic(PalletIdxFrom(0), CallIdxFrom(7), args, alicePublicKey, fixedSigner, ExtrinsicNonceFrom(0), makeChainParams())
	require.NoError(t, err)
	b := ext.Bytes()
	_, prefixLen, err := DecodeCompact(b)
	require.NoError(t, err)
	payload := b[prefixLen:]
	eraOffset := 1 + 1 + 32 + 1 + 64
	require.Equal(t, byte(0x00), payload[eraOffset])
}

func TestBuildSignedExtrinsicDifferentNoncesProduceDifferentBytes(t *testing.T) {
	args := buildRemarkArgs([]byte("x"))
	cp := makeChainParams()
	a, err := BuildSignedExtrinsic(PalletIdxFrom(0), CallIdxFrom(7), args, alicePublicKey, fixedSigner, ExtrinsicNonceFrom(0), cp)
	require.NoError(t, err)
	b, err := BuildSignedExtrinsic(PalletIdxFrom(0), CallIdxFrom(7), args, alicePublicKey, fixedSigner, ExtrinsicNonceFrom(1), cp)
	require.NoError(t, err)
	require.NotEqual(t, a.Bytes(), b.Bytes())
}

func TestExtractSignerReturnsFalseForUnsignedExtrinsic(t *testing.T) {
	unsigned := ExtrinsicBytesFromBytes([]byte{0x10, 0x04, 0x03, 0x00, 0x00})
	_, ok := ExtractSigner(unsigned)
	require.False(t, ok)
}

func TestExtractCallReturnsFalseForUnsignedExtrinsic(t *testing.T) {
	unsigned := ExtrinsicBytesFromBytes([]byte{0x10, 0x04, 0x03, 0x00, 0x00})
	_, ok := ExtractCall(unsigned)
	require.False(t, ok)
}

func TestExtractSignerReturnsFalseForEmptyInput(t *testing.T) {
	_, ok := ExtractSigner(ExtrinsicBytesFromBytes([]byte{}))
	require.False(t, ok)
}

func TestBuildSignedExtrinsicPayloadAbove256BytesUsesBlake2Hash(t *testing.T) {
	bigRemark := make([]byte, 1024)
	for i := range bigRemark {
		bigRemark[i] = 0xab
	}
	args := buildRemarkArgs(bigRemark)
	var captured []int
	capturingSigner := func(msg []byte) (Signature, error) {
		captured = append(captured, len(msg))
		return fixedSignature, nil
	}
	ext, err := BuildSignedExtrinsic(PalletIdxFrom(0), CallIdxFrom(7), args, alicePublicKey, capturingSigner, ExtrinsicNonceFrom(0), makeChainParams())
	require.NoError(t, err)
	require.Equal(t, []int{32}, captured)
	extracted, ok := ExtractCall(ext)
	require.True(t, ok)
	require.Equal(t, args.Bytes(), extracted.Args.Bytes())
}

func TestSigningClosureErrorPropagates(t *testing.T) {
	failingSigner := func(_ []byte) (Signature, error) {
		return Signature{}, errors.New("hardware wallet disconnected")
	}
	_, err := BuildSignedExtrinsic(PalletIdxFrom(0), CallIdxFrom(7), CallArgsFromBytes([]byte{}), alicePublicKey, failingSigner, ExtrinsicNonceFrom(0), makeChainParams())
	require.ErrorContains(t, err, "hardware wallet disconnected")
}

func TestMatchesE2EExtrinsicVectorsFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "e2e", "extrinsic-vectors.json"))
	require.NoError(t, err)

	var vectors extrinsicVectors
	require.NoError(t, json.Unmarshal(raw, &vectors))

	for _, c := range vectors.Cases {
		publicKey := PubkeyFromBytes(mustHex32(stripHex(c.PublicKey)))
		signature := SignatureFromBytes(mustHex64(stripHex(c.FixedSignature)))
		callArgs := CallArgsFromBytes(unhexBytes(t, c.CallArgs))
		chain := ChainParams{
			GenesisHash: GenesisHashFromBytes(mustHex32(stripHex(c.ChainParams.GenesisHash))),
			SpecVersion: SpecVersionFrom(c.ChainParams.SpecVersion),
			TxVersion:   TxVersionFrom(c.ChainParams.TxVersion),
		}

		signer := func(_ []byte) (Signature, error) {
			return signature, nil
		}

		built, err := BuildSignedExtrinsic(PalletIdxFrom(c.PalletIdx), CallIdxFrom(c.CallIdx), callArgs, publicKey, signer, ExtrinsicNonceFrom(c.Nonce), chain)
		require.NoError(t, err)
		require.Equal(t, unhexBytes(t, c.ExpectedExtrinsic), built.Bytes(), "case %s", c.Label)
	}
}

func stripHex(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}
