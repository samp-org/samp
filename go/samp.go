package samp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	SAMPVersion byte = 0x10

	ChannelHeaderSize = 12
	ThreadHeaderSize  = 18

	ChannelNameMax = 32
	ChannelDescMax = 128
	CapsuleSize    = 33
)

type ContentType byte

const (
	ContentTypePublic        ContentType = 0x10
	ContentTypeEncrypted     ContentType = 0x11
	ContentTypeThread        ContentType = 0x12
	ContentTypeChannelCreate ContentType = 0x13
	ContentTypeChannel       ContentType = 0x14
	ContentTypeGroup         ContentType = 0x15
)

func (c ContentType) Byte() byte { return byte(c) }

func ContentTypeFromByte(b byte) (ContentType, error) {
	if b&0xF0 != SAMPVersion {
		return 0, errVersion(b & 0xF0)
	}
	switch b & 0x0F {
	case 0x00, 0x01, 0x02, 0x03, 0x04, 0x05:
		return ContentType(b), nil
	case 0x06, 0x07:
		return 0, errReserved(b)
	default:
		return ContentType(b), nil
	}
}

var (
	ErrInsufficientData   = errors.New("samp: insufficient data")
	ErrInvalidUTF8        = errors.New("samp: content is not valid UTF-8")
	ErrInvalidChannelName = errors.New("samp: channel name must be 1-32 bytes")
	ErrInvalidChannelDesc = errors.New("samp: channel description must be 0-128 bytes")
)

func errReserved(b byte) error {
	return fmt.Errorf("samp: reserved content type: 0x%02x", b)
}

func errVersion(b byte) error {
	return fmt.Errorf("samp: unsupported version: 0x%02x", b)
}

func encodeBlockRef(out []byte, r BlockRef) {
	binary.LittleEndian.PutUint32(out[0:4], r.block.n)
	binary.LittleEndian.PutUint16(out[4:6], r.index.i)
}

func decodeBlockRef(data []byte) BlockRef {
	return BlockRef{
		block: BlockNumber{binary.LittleEndian.Uint32(data[0:4])},
		index: ExtIndex{binary.LittleEndian.Uint16(data[4:6])},
	}
}

type Remark interface {
	ContentType() ContentType
	remarkSealed()
}

type PublicRemark struct {
	Recipient Pubkey
	Body      string
}

func (r PublicRemark) ContentType() ContentType { return ContentTypePublic }
func (PublicRemark) remarkSealed()              {}

type EncryptedRemark struct {
	ViewTag    ViewTag
	Nonce      Nonce
	Ciphertext Ciphertext
}

func (r EncryptedRemark) ContentType() ContentType { return ContentTypeEncrypted }
func (EncryptedRemark) remarkSealed()              {}

type ThreadRemark struct {
	ViewTag    ViewTag
	Nonce      Nonce
	Ciphertext Ciphertext
}

func (r ThreadRemark) ContentType() ContentType { return ContentTypeThread }
func (ThreadRemark) remarkSealed()              {}

type ChannelCreateRemark struct {
	Name        ChannelName
	Description ChannelDescription
}

func (r ChannelCreateRemark) ContentType() ContentType { return ContentTypeChannelCreate }
func (ChannelCreateRemark) remarkSealed()              {}

type ChannelRemark struct {
	ChannelRef BlockRef
	ReplyTo    BlockRef
	Continues  BlockRef
	Body       []byte
}

func (r ChannelRemark) ContentType() ContentType { return ContentTypeChannel }
func (ChannelRemark) remarkSealed()              {}

type GroupRemark struct {
	Nonce   Nonce
	Content []byte
}

func (r GroupRemark) ContentType() ContentType { return ContentTypeGroup }
func (GroupRemark) remarkSealed()              {}

type ApplicationRemark struct {
	Tag     byte
	Payload []byte
}

func (r ApplicationRemark) ContentType() ContentType { return ContentType(r.Tag) }
func (ApplicationRemark) remarkSealed()              {}

func EncodePublic(recipient Pubkey, body string) RemarkBytes {
	b := []byte(body)
	out := make([]byte, 0, 33+len(b))
	out = append(out, ContentTypePublic.Byte())
	out = append(out, recipient.b[:]...)
	out = append(out, b...)
	return RemarkBytes{out}
}

func EncodeEncrypted(contentType ContentType, viewTag ViewTag, nonce Nonce, ciphertext Ciphertext) RemarkBytes {
	out := make([]byte, 0, 14+len(ciphertext.b))
	out = append(out, contentType.Byte(), viewTag.v)
	out = append(out, nonce.b[:]...)
	out = append(out, ciphertext.b...)
	return RemarkBytes{out}
}

func EncodeChannelMsg(channelRef, replyTo, continues BlockRef, body []byte) RemarkBytes {
	out := make([]byte, 19, 19+len(body))
	out[0] = ContentTypeChannel.Byte()
	encodeBlockRef(out[1:7], channelRef)
	encodeBlockRef(out[7:13], replyTo)
	encodeBlockRef(out[13:19], continues)
	out = append(out, body...)
	return RemarkBytes{out}
}

func EncodeChannelCreate(name ChannelName, description ChannelDescription) RemarkBytes {
	nb := []byte(name.s)
	db := []byte(description.s)
	out := make([]byte, 0, 3+len(nb)+len(db))
	out = append(out, ContentTypeChannelCreate.Byte(), byte(len(nb)))
	out = append(out, nb...)
	out = append(out, byte(len(db)))
	out = append(out, db...)
	return RemarkBytes{out}
}

func EncodeGroup(nonce Nonce, ephPubkey EphPubkey, capsules Capsules, ciphertext Ciphertext) RemarkBytes {
	out := make([]byte, 0, 45+len(capsules.b)+len(ciphertext.b))
	out = append(out, ContentTypeGroup.Byte())
	out = append(out, nonce.b[:]...)
	out = append(out, ephPubkey.b[:]...)
	out = append(out, capsules.b...)
	out = append(out, ciphertext.b...)
	return RemarkBytes{out}
}

func DecodeRemark(remark RemarkBytes) (Remark, error) {
	data := remark.b
	if len(data) == 0 {
		return nil, ErrInsufficientData
	}
	ctByte := data[0]
	if ctByte&0xF0 != SAMPVersion {
		return nil, errVersion(ctByte & 0xF0)
	}

	switch ctByte & 0x0F {
	case 0x00:
		if len(data) < 33 {
			return nil, ErrInsufficientData
		}
		body := data[33:]
		if !utf8.Valid(body) {
			return nil, ErrInvalidUTF8
		}
		var pk [32]byte
		copy(pk[:], data[1:33])
		return PublicRemark{Recipient: Pubkey{pk}, Body: string(body)}, nil

	case 0x01, 0x02:
		if len(data) < 14 {
			return nil, ErrInsufficientData
		}
		var n [12]byte
		copy(n[:], data[2:14])
		ct := make([]byte, len(data)-14)
		copy(ct, data[14:])
		if ctByte&0x0F == 0x01 {
			return EncryptedRemark{ViewTag: ViewTag{data[1]}, Nonce: Nonce{n}, Ciphertext: Ciphertext{ct}}, nil
		}
		return ThreadRemark{ViewTag: ViewTag{data[1]}, Nonce: Nonce{n}, Ciphertext: Ciphertext{ct}}, nil

	case 0x03:
		name, desc, err := decodeChannelCreatePayload(data[1:])
		if err != nil {
			return nil, err
		}
		cn, err := ChannelNameParse(name)
		if err != nil {
			return nil, err
		}
		cd, err := ChannelDescriptionParse(desc)
		if err != nil {
			return nil, err
		}
		return ChannelCreateRemark{Name: cn, Description: cd}, nil

	case 0x04:
		if len(data) < 19 {
			return nil, ErrInsufficientData
		}
		return ChannelRemark{
			ChannelRef: decodeBlockRef(data[1:7]),
			ReplyTo:    decodeBlockRef(data[7:13]),
			Continues:  decodeBlockRef(data[13:19]),
			Body:       data[19:],
		}, nil

	case 0x05:
		if len(data) < 13 {
			return nil, ErrInsufficientData
		}
		var n [12]byte
		copy(n[:], data[1:13])
		return GroupRemark{Nonce: Nonce{n}, Content: data[13:]}, nil

	case 0x06, 0x07:
		return nil, errReserved(ctByte)

	default:
		return ApplicationRemark{Tag: ctByte, Payload: data[1:]}, nil
	}
}

func decodeChannelCreatePayload(data []byte) (string, string, error) {
	if len(data) < 2 {
		return "", "", ErrInsufficientData
	}
	nameLen := int(data[0])
	if nameLen == 0 || nameLen > ChannelNameMax {
		return "", "", ErrInvalidChannelName
	}
	if len(data) < 1+nameLen+1 {
		return "", "", ErrInsufficientData
	}
	name := string(data[1 : 1+nameLen])
	descOff := 1 + nameLen
	descLen := int(data[descOff])
	if descLen > ChannelDescMax {
		return "", "", ErrInvalidChannelDesc
	}
	if len(data) < descOff+1+descLen {
		return "", "", ErrInsufficientData
	}
	return name, string(data[descOff+1 : descOff+1+descLen]), nil
}

func EncodeThreadContent(thread, replyTo, continues BlockRef, body []byte) Plaintext {
	out := make([]byte, ThreadHeaderSize, ThreadHeaderSize+len(body))
	encodeBlockRef(out[0:6], thread)
	encodeBlockRef(out[6:12], replyTo)
	encodeBlockRef(out[12:18], continues)
	out = append(out, body...)
	return Plaintext{out}
}

func DecodeThreadContent(content Plaintext) (thread, replyTo, continues BlockRef, body []byte, err error) {
	d := content.b
	if len(d) < ThreadHeaderSize {
		return BlockRef{}, BlockRef{}, BlockRef{}, nil, ErrInsufficientData
	}
	return decodeBlockRef(d[0:6]), decodeBlockRef(d[6:12]), decodeBlockRef(d[12:18]), d[18:], nil
}

func EncodeChannelContent(replyTo, continues BlockRef, body []byte) Plaintext {
	out := make([]byte, ChannelHeaderSize, ChannelHeaderSize+len(body))
	encodeBlockRef(out[0:6], replyTo)
	encodeBlockRef(out[6:12], continues)
	out = append(out, body...)
	return Plaintext{out}
}

func DecodeChannelContent(content Plaintext) (replyTo, continues BlockRef, body []byte, err error) {
	d := content.b
	if len(d) < ChannelHeaderSize {
		return BlockRef{}, BlockRef{}, nil, ErrInsufficientData
	}
	return decodeBlockRef(d[0:6]), decodeBlockRef(d[6:12]), d[12:], nil
}

func DecodeGroupContent(content Plaintext) (groupRef, replyTo, continues BlockRef, body []byte, err error) {
	d := content.b
	if len(d) < ThreadHeaderSize {
		return BlockRef{}, BlockRef{}, BlockRef{}, nil, ErrInsufficientData
	}
	return decodeBlockRef(d[0:6]), decodeBlockRef(d[6:12]), decodeBlockRef(d[12:18]), d[18:], nil
}

func EncodeGroupMembers(memberPubkeys []Pubkey) []byte {
	out := make([]byte, 0, 1+len(memberPubkeys)*32)
	out = append(out, byte(len(memberPubkeys)))
	for _, pk := range memberPubkeys {
		out = append(out, pk.b[:]...)
	}
	return out
}

func DecodeGroupMembers(data []byte) ([]Pubkey, []byte, error) {
	if len(data) < 1 {
		return nil, nil, ErrInsufficientData
	}
	count := int(data[0])
	expected := 1 + count*32
	if len(data) < expected {
		return nil, nil, ErrInsufficientData
	}
	members := make([]Pubkey, count)
	for i := 0; i < count; i++ {
		var pk [32]byte
		copy(pk[:], data[1+i*32:1+(i+1)*32])
		members[i] = Pubkey{pk}
	}
	return members, data[expected:], nil
}
