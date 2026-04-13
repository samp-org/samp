package samp

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

const (
	extVersionSigned     = 0x84
	addrTypeId           = 0x00
	sigTypeSr25519       = 0x01
	eraImmortal          = 0x00
	metadataHashDisabled = 0x00
	signedHeaderLen      = 99
	minSignedExtrinsic   = 103
	minSignerPayload     = 34
)

type ExtrinsicError struct{ Msg string }

func (e *ExtrinsicError) Error() string { return "samp: extrinsic: " + e.Msg }

func newExtrinsicError(msg string) *ExtrinsicError { return &ExtrinsicError{Msg: msg} }

type ChainParams struct {
	GenesisHash GenesisHash
	SpecVersion SpecVersion
	TxVersion   TxVersion
}

type ExtractedCall struct {
	Pallet PalletIdx
	Call   CallIdx
	Args   CallArgs
}

type SignFn func(msg []byte) (Signature, error)

func BuildSignedExtrinsic(
	pallet PalletIdx,
	call CallIdx,
	args CallArgs,
	publicKey Pubkey,
	sign SignFn,
	nonce ExtrinsicNonce,
	chain ChainParams,
) (ExtrinsicBytes, error) {
	callArgs := args.b
	callData := make([]byte, 0, 2+len(callArgs))
	callData = append(callData, pallet.v, call.v)
	callData = append(callData, callArgs...)

	var specBytes [4]byte
	binary.LittleEndian.PutUint32(specBytes[:], chain.SpecVersion.v)
	var txBytes [4]byte
	binary.LittleEndian.PutUint32(txBytes[:], chain.TxVersion.v)

	genesis := chain.GenesisHash.b

	signingPayload := make([]byte, 0, len(callData)+1+5+1+1+4+4+32+32+1)
	signingPayload = append(signingPayload, callData...)
	signingPayload = append(signingPayload, eraImmortal)
	signingPayload = append(signingPayload, EncodeCompact(uint64(nonce.n))...)
	signingPayload = append(signingPayload, 0x00)
	signingPayload = append(signingPayload, metadataHashDisabled)
	signingPayload = append(signingPayload, specBytes[:]...)
	signingPayload = append(signingPayload, txBytes[:]...)
	signingPayload = append(signingPayload, genesis[:]...)
	signingPayload = append(signingPayload, genesis[:]...)
	signingPayload = append(signingPayload, 0x00)

	var toSign []byte
	if len(signingPayload) > 256 {
		hash := blake2b.Sum256(signingPayload)
		toSign = hash[:]
	} else {
		toSign = signingPayload
	}

	signature, err := sign(toSign)
	if err != nil {
		return ExtrinsicBytes{}, err
	}
	sigBytes := signature.b
	pkBytes := publicKey.b

	extrinsicPayload := make([]byte, 0, signedHeaderLen+5+len(callData))
	extrinsicPayload = append(extrinsicPayload, extVersionSigned, addrTypeId)
	extrinsicPayload = append(extrinsicPayload, pkBytes[:]...)
	extrinsicPayload = append(extrinsicPayload, sigTypeSr25519)
	extrinsicPayload = append(extrinsicPayload, sigBytes[:]...)
	extrinsicPayload = append(extrinsicPayload, eraImmortal)
	extrinsicPayload = append(extrinsicPayload, EncodeCompact(uint64(nonce.n))...)
	extrinsicPayload = append(extrinsicPayload, 0x00)
	extrinsicPayload = append(extrinsicPayload, metadataHashDisabled)
	extrinsicPayload = append(extrinsicPayload, callData...)

	if uint64(len(extrinsicPayload)) > 1<<32-1 {
		return ExtrinsicBytes{}, newExtrinsicError(fmt.Sprintf("extrinsic payload too large: %d bytes", len(extrinsicPayload)))
	}

	out := make([]byte, 0, len(extrinsicPayload)+5)
	out = append(out, EncodeCompact(uint64(len(extrinsicPayload)))...)
	out = append(out, extrinsicPayload...)
	return ExtrinsicBytes{out}, nil
}

func ExtractSigner(ext ExtrinsicBytes) (Pubkey, bool) {
	bytes := ext.b
	_, prefixLen, err := DecodeCompact(bytes)
	if err != nil {
		return Pubkey{}, false
	}
	payload := bytes[prefixLen:]
	if len(payload) < minSignerPayload || payload[0]&0x80 == 0 || payload[1] != addrTypeId {
		return Pubkey{}, false
	}
	var out [32]byte
	copy(out[:], payload[2:34])
	return Pubkey{out}, true
}

func ExtractCall(ext ExtrinsicBytes) (ExtractedCall, bool) {
	bytes := ext.b
	_, prefixLen, err := DecodeCompact(bytes)
	if err != nil {
		return ExtractedCall{}, false
	}
	payload := bytes[prefixLen:]

	if len(payload) < minSignedExtrinsic || payload[0]&0x80 == 0 {
		return ExtractedCall{}, false
	}

	offset := signedHeaderLen
	if offset >= len(payload) {
		return ExtractedCall{}, false
	}
	if payload[offset] != 0x00 {
		offset += 2
	} else {
		offset++
	}

	_, nonceLen, err := DecodeCompact(payload[offset:])
	if err != nil {
		return ExtractedCall{}, false
	}
	offset += nonceLen

	_, tipLen, err := DecodeCompact(payload[offset:])
	if err != nil {
		return ExtractedCall{}, false
	}
	offset += tipLen

	offset++

	if offset+2 > len(payload) {
		return ExtractedCall{}, false
	}
	pallet := payload[offset]
	call := payload[offset+1]
	offset += 2

	if offset > len(payload) {
		return ExtractedCall{}, false
	}

	return ExtractedCall{
		Pallet: PalletIdx{pallet},
		Call:   CallIdx{call},
		Args:   CallArgs{payload[offset:]},
	}, true
}
