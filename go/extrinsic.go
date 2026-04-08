package samp

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

const (
	extVersionSigned      = 0x84
	addrTypeId            = 0x00
	sigTypeSr25519        = 0x01
	eraImmortal           = 0x00
	metadataHashDisabled  = 0x00
	signedHeaderLen       = 99
	minSignedExtrinsic    = 103
	minSignerPayload      = 34
)

type ExtrinsicError struct {
	Msg string
}

func (e *ExtrinsicError) Error() string {
	return "samp: extrinsic: " + e.Msg
}

func newExtrinsicError(msg string) *ExtrinsicError {
	return &ExtrinsicError{Msg: msg}
}

type ChainParams struct {
	GenesisHash [32]byte
	SpecVersion uint32
	TxVersion   uint32
}

type ExtractedCall struct {
	Pallet uint8
	Call   uint8
	Args   []byte
}

type SignFn func(msg []byte) ([64]byte, error)

func BuildSignedExtrinsic(
	palletIdx, callIdx uint8,
	callArgs []byte,
	publicKey [32]byte,
	sign SignFn,
	nonce uint32,
	chain ChainParams,
) ([]byte, error) {
	callData := make([]byte, 0, 2+len(callArgs))
	callData = append(callData, palletIdx, callIdx)
	callData = append(callData, callArgs...)

	var specBytes [4]byte
	binary.LittleEndian.PutUint32(specBytes[:], chain.SpecVersion)
	var txBytes [4]byte
	binary.LittleEndian.PutUint32(txBytes[:], chain.TxVersion)

	signingPayload := make([]byte, 0, len(callData)+1+5+1+1+4+4+32+32+1)
	signingPayload = append(signingPayload, callData...)
	signingPayload = append(signingPayload, eraImmortal)
	signingPayload = append(signingPayload, EncodeCompact(uint64(nonce))...)
	signingPayload = append(signingPayload, 0x00)
	signingPayload = append(signingPayload, metadataHashDisabled)
	signingPayload = append(signingPayload, specBytes[:]...)
	signingPayload = append(signingPayload, txBytes[:]...)
	signingPayload = append(signingPayload, chain.GenesisHash[:]...)
	signingPayload = append(signingPayload, chain.GenesisHash[:]...)
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
		return nil, err
	}

	extrinsicPayload := make([]byte, 0, signedHeaderLen+5+len(callData))
	extrinsicPayload = append(extrinsicPayload, extVersionSigned, addrTypeId)
	extrinsicPayload = append(extrinsicPayload, publicKey[:]...)
	extrinsicPayload = append(extrinsicPayload, sigTypeSr25519)
	extrinsicPayload = append(extrinsicPayload, signature[:]...)
	extrinsicPayload = append(extrinsicPayload, eraImmortal)
	extrinsicPayload = append(extrinsicPayload, EncodeCompact(uint64(nonce))...)
	extrinsicPayload = append(extrinsicPayload, 0x00)
	extrinsicPayload = append(extrinsicPayload, metadataHashDisabled)
	extrinsicPayload = append(extrinsicPayload, callData...)

	if uint64(len(extrinsicPayload)) > 1<<32-1 {
		return nil, newExtrinsicError(fmt.Sprintf("extrinsic payload too large: %d bytes", len(extrinsicPayload)))
	}

	out := make([]byte, 0, len(extrinsicPayload)+5)
	out = append(out, EncodeCompact(uint64(len(extrinsicPayload)))...)
	out = append(out, extrinsicPayload...)
	return out, nil
}

func ExtractSigner(extrinsicBytes []byte) ([32]byte, bool) {
	var zero [32]byte
	_, prefixLen, err := DecodeCompact(extrinsicBytes)
	if err != nil {
		return zero, false
	}
	payload := extrinsicBytes[prefixLen:]
	if len(payload) < minSignerPayload || payload[0]&0x80 == 0 || payload[1] != addrTypeId {
		return zero, false
	}
	var out [32]byte
	copy(out[:], payload[2:34])
	return out, true
}

func ExtractCall(extrinsicBytes []byte) (*ExtractedCall, bool) {
	_, prefixLen, err := DecodeCompact(extrinsicBytes)
	if err != nil {
		return nil, false
	}
	payload := extrinsicBytes[prefixLen:]

	if len(payload) < minSignedExtrinsic || payload[0]&0x80 == 0 {
		return nil, false
	}

	offset := signedHeaderLen
	if offset >= len(payload) {
		return nil, false
	}
	if payload[offset] != 0x00 {
		offset += 2
	} else {
		offset++
	}

	_, nonceLen, err := DecodeCompact(payload[offset:])
	if err != nil {
		return nil, false
	}
	offset += nonceLen

	_, tipLen, err := DecodeCompact(payload[offset:])
	if err != nil {
		return nil, false
	}
	offset += tipLen

	offset++

	if offset+2 > len(payload) {
		return nil, false
	}
	pallet := payload[offset]
	call := payload[offset+1]
	offset += 2

	if offset > len(payload) {
		return nil, false
	}

	return &ExtractedCall{Pallet: pallet, Call: call, Args: payload[offset:]}, true
}
