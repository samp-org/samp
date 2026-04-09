package samp

import (
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrBlockNumberOverflow   = errors.New("samp: block number overflow")
	ErrExtIndexOverflow      = errors.New("samp: ext index overflow")
	ErrInvalidCapsules       = errors.New("samp: capsule length not multiple of 33")
	ErrSs58PrefixUnsupported = errors.New("samp: ss58 prefix unsupported")
	ErrSs58InvalidBase58     = errors.New("samp: ss58 invalid base58")
	ErrSs58TooShort          = errors.New("samp: ss58 too short")
	ErrSs58BadChecksum       = errors.New("samp: ss58 bad checksum")
)

type BlockNumber struct{ n uint32 }

func BlockNumberFrom(n uint32) BlockNumber { return BlockNumber{n} }
func (b BlockNumber) Get() uint32          { return b.n }
func (b BlockNumber) String() string       { return fmt.Sprintf("#%d", b.n) }
func BlockNumberFromUint64(n uint64) (BlockNumber, error) {
	if n > 0xFFFFFFFF {
		return BlockNumber{}, ErrBlockNumberOverflow
	}
	return BlockNumber{uint32(n)}, nil
}

type ExtIndex struct{ i uint16 }

func ExtIndexFrom(i uint16) ExtIndex { return ExtIndex{i} }
func (e ExtIndex) Get() uint16       { return e.i }
func (e ExtIndex) String() string    { return fmt.Sprintf(".%d", e.i) }
func ExtIndexFromInt(n int) (ExtIndex, error) {
	if n < 0 || n > 0xFFFF {
		return ExtIndex{}, ErrExtIndexOverflow
	}
	return ExtIndex{uint16(n)}, nil
}

type BlockRef struct {
	block BlockNumber
	index ExtIndex
}

var BlockRefZero = BlockRef{}

func BlockRefNew(block BlockNumber, index ExtIndex) BlockRef { return BlockRef{block, index} }
func BlockRefFromParts(block uint32, index uint16) BlockRef {
	return BlockRef{BlockNumber{block}, ExtIndex{index}}
}
func (r BlockRef) Block() BlockNumber { return r.block }
func (r BlockRef) Index() ExtIndex    { return r.index }
func (r BlockRef) IsZero() bool       { return r.block.n == 0 && r.index.i == 0 }
func (r BlockRef) String() string     { return fmt.Sprintf("#%d.%d", r.block.n, r.index.i) }

type Pubkey struct{ b [32]byte }

var PubkeyZero = Pubkey{}

func PubkeyFromBytes(b [32]byte) Pubkey { return Pubkey{b} }
func (p Pubkey) Bytes() [32]byte        { return p.b }
func (p Pubkey) String() string         { return "Pubkey(0x" + hex.EncodeToString(p.b[:]) + ")" }
func (p Pubkey) ToSs58(prefix Ss58Prefix) Ss58Address {
	return ss58Encode(p, prefix)
}

type Signature struct{ b [64]byte }

func SignatureFromBytes(b [64]byte) Signature { return Signature{b} }
func (s Signature) Bytes() [64]byte           { return s.b }
func (s Signature) String() string            { return "Signature(0x" + hex.EncodeToString(s.b[:]) + ")" }

type GenesisHash struct{ b [32]byte }

func GenesisHashFromBytes(b [32]byte) GenesisHash { return GenesisHash{b} }
func (g GenesisHash) Bytes() [32]byte             { return g.b }
func (g GenesisHash) String() string {
	return "GenesisHash(0x" + hex.EncodeToString(g.b[:]) + ")"
}

type Nonce struct{ b [12]byte }

var NonceZero = Nonce{}

func NonceFromBytes(b [12]byte) Nonce { return Nonce{b} }
func (n Nonce) Bytes() [12]byte       { return n.b }
func (n Nonce) String() string        { return "Nonce(0x" + hex.EncodeToString(n.b[:]) + ")" }

// chachaNonce returns the 12 raw bytes for the AEAD boundary only.
func (n Nonce) chachaNonce() []byte { b := n.b; return b[:] }

type ExtrinsicNonce struct{ n uint32 }

func ExtrinsicNonceFrom(n uint32) ExtrinsicNonce { return ExtrinsicNonce{n} }
func (e ExtrinsicNonce) Get() uint32             { return e.n }

type SpecVersion struct{ v uint32 }

func SpecVersionFrom(v uint32) SpecVersion { return SpecVersion{v} }
func (s SpecVersion) Get() uint32          { return s.v }

type TxVersion struct{ v uint32 }

func TxVersionFrom(v uint32) TxVersion { return TxVersion{v} }
func (t TxVersion) Get() uint32        { return t.v }

type PalletIdx struct{ v uint8 }

func PalletIdxFrom(v uint8) PalletIdx { return PalletIdx{v} }
func (p PalletIdx) Get() uint8        { return p.v }

type CallIdx struct{ v uint8 }

func CallIdxFrom(v uint8) CallIdx { return CallIdx{v} }
func (c CallIdx) Get() uint8      { return c.v }

type ViewTag struct{ v uint8 }

func ViewTagFrom(v uint8) ViewTag { return ViewTag{v} }
func (v ViewTag) Get() uint8      { return v.v }
func (v ViewTag) String() string  { return fmt.Sprintf("ViewTag(0x%02x)", v.v) }

type EphPubkey struct{ b [32]byte }

func EphPubkeyFromBytes(b [32]byte) EphPubkey { return EphPubkey{b} }
func (e EphPubkey) Bytes() [32]byte           { return e.b }

type Plaintext struct{ b []byte }

func PlaintextFromBytes(b []byte) Plaintext { return Plaintext{b} }
func (p Plaintext) Bytes() []byte           { return p.b }
func (p Plaintext) Len() int                { return len(p.b) }
func (p Plaintext) String() string          { return fmt.Sprintf("Plaintext(%d bytes)", len(p.b)) }

type Ciphertext struct{ b []byte }

func CiphertextFromBytes(b []byte) Ciphertext { return Ciphertext{b} }
func (c Ciphertext) Bytes() []byte            { return c.b }
func (c Ciphertext) Len() int                 { return len(c.b) }
func (c Ciphertext) String() string           { return fmt.Sprintf("Ciphertext(%d bytes)", len(c.b)) }

type Capsules struct{ b []byte }

func CapsulesFromBytes(b []byte) (Capsules, error) {
	if len(b)%CapsuleSize != 0 {
		return Capsules{}, ErrInvalidCapsules
	}
	return Capsules{b}, nil
}
func (c Capsules) Bytes() []byte  { return c.b }
func (c Capsules) Count() int     { return len(c.b) / CapsuleSize }
func (c Capsules) String() string { return fmt.Sprintf("Capsules(%d entries)", c.Count()) }

type RemarkBytes struct{ b []byte }

func RemarkBytesFromBytes(b []byte) RemarkBytes { return RemarkBytes{b} }
func (r RemarkBytes) Bytes() []byte             { return r.b }
func (r RemarkBytes) Len() int                  { return len(r.b) }

type ExtrinsicBytes struct{ b []byte }

func ExtrinsicBytesFromBytes(b []byte) ExtrinsicBytes { return ExtrinsicBytes{b} }
func (e ExtrinsicBytes) Bytes() []byte                { return e.b }
func (e ExtrinsicBytes) Len() int                     { return len(e.b) }

type CallArgs struct{ b []byte }

func CallArgsFromBytes(b []byte) CallArgs { return CallArgs{b} }
func (c CallArgs) Bytes() []byte          { return c.b }
func (c CallArgs) Len() int               { return len(c.b) }

type ChannelName struct{ s string }

func ChannelNameParse(s string) (ChannelName, error) {
	if len(s) == 0 || len(s) > ChannelNameMax {
		return ChannelName{}, ErrInvalidChannelName
	}
	return ChannelName{s}, nil
}
func (c ChannelName) String() string { return c.s }
func (c ChannelName) Len() int       { return len(c.s) }

type ChannelDescription struct{ s string }

func ChannelDescriptionParse(s string) (ChannelDescription, error) {
	if len(s) > ChannelDescMax {
		return ChannelDescription{}, ErrInvalidChannelDesc
	}
	return ChannelDescription{s}, nil
}
func (c ChannelDescription) String() string { return c.s }
func (c ChannelDescription) Len() int       { return len(c.s) }

type Ss58Prefix struct{ v uint16 }

var (
	Ss58SubstrateGeneric = Ss58Prefix{42}
	Ss58Polkadot         = Ss58Prefix{0}
	Ss58Kusama           = Ss58Prefix{2}
)

func Ss58PrefixNew(v uint16) (Ss58Prefix, error) {
	if v > 63 {
		return Ss58Prefix{}, fmt.Errorf("%w: %d", ErrSs58PrefixUnsupported, v)
	}
	return Ss58Prefix{v}, nil
}
func (p Ss58Prefix) Get() uint16 { return p.v }

type Ss58Address struct {
	address string
	pubkey  Pubkey
	prefix  Ss58Prefix
}

func Ss58AddressParse(s string) (Ss58Address, error) { return ss58Decode(s) }
func Ss58AddressEncode(pubkey Pubkey, prefix Ss58Prefix) Ss58Address {
	return ss58Encode(pubkey, prefix)
}
func (a Ss58Address) String() string     { return a.address }
func (a Ss58Address) Pubkey() Pubkey     { return a.pubkey }
func (a Ss58Address) Prefix() Ss58Prefix { return a.prefix }
