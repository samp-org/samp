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

var ErrInsufficientData = errors.New("samp: insufficient data")
var ErrInvalidUTF8 = errors.New("samp: content is not valid UTF-8")
var ErrInvalidChannelName = errors.New("samp: channel name must be 1-32 bytes")
var ErrInvalidChannelDesc = errors.New("samp: channel description must be 0-128 bytes")

func errReserved(b byte) error {
	return fmt.Errorf("samp: reserved content type: 0x%02x", b)
}

func errVersion(b byte) error {
	return fmt.Errorf("samp: unsupported version: 0x%02x", b)
}

type BlockRef struct {
	Block uint32
	Index uint16
}

var BlockRefZero = BlockRef{0, 0}

func encodeBlockRef(out []byte, r BlockRef) {
	binary.LittleEndian.PutUint32(out[0:4], r.Block)
	binary.LittleEndian.PutUint16(out[4:6], r.Index)
}

func decodeBlockRef(data []byte) BlockRef {
	return BlockRef{
		Block: binary.LittleEndian.Uint32(data[0:4]),
		Index: binary.LittleEndian.Uint16(data[4:6]),
	}
}

type Remark struct {
	ContentType ContentType
	Recipient   [32]byte
	ViewTag     byte
	Nonce       [12]byte
	Content     []byte
}

func EncodePublic(recipient [32]byte, body []byte) []byte {
	out := make([]byte, 0, 33+len(body))
	out = append(out, ContentTypePublic.Byte())
	out = append(out, recipient[:]...)
	out = append(out, body...)
	return out
}

func EncodeEncrypted(contentType ContentType, viewTag byte, nonce [12]byte, content []byte) []byte {
	out := make([]byte, 0, 14+len(content))
	out = append(out, contentType.Byte(), viewTag)
	out = append(out, nonce[:]...)
	out = append(out, content...)
	return out
}

func EncodeChannelMsg(channelRef, replyTo, continues BlockRef, body []byte) []byte {
	out := make([]byte, 19, 19+len(body))
	out[0] = ContentTypeChannel.Byte()
	encodeBlockRef(out[1:7], channelRef)
	encodeBlockRef(out[7:13], replyTo)
	encodeBlockRef(out[13:19], continues)
	out = append(out, body...)
	return out
}

func EncodeChannelCreate(name, description string) ([]byte, error) {
	nb := []byte(name)
	db := []byte(description)
	if len(nb) == 0 || len(nb) > ChannelNameMax {
		return nil, ErrInvalidChannelName
	}
	if len(db) > ChannelDescMax {
		return nil, ErrInvalidChannelDesc
	}
	out := make([]byte, 0, 3+len(nb)+len(db))
	out = append(out, ContentTypeChannelCreate.Byte(), byte(len(nb)))
	out = append(out, nb...)
	out = append(out, byte(len(db)))
	out = append(out, db...)
	return out, nil
}

func DecodeRemark(data []byte) (*Remark, error) {
	if len(data) == 0 {
		return nil, ErrInsufficientData
	}
	ct, err := ContentTypeFromByte(data[0])
	if err != nil {
		return nil, err
	}

	switch ct {
	case ContentTypePublic:
		if len(data) < 33 {
			return nil, ErrInsufficientData
		}
		body := data[33:]
		if !utf8.Valid(body) {
			return nil, ErrInvalidUTF8
		}
		var r Remark
		r.ContentType = ct
		copy(r.Recipient[:], data[1:33])
		r.Content = body
		return &r, nil

	case ContentTypeEncrypted, ContentTypeThread:
		if len(data) < 14 {
			return nil, ErrInsufficientData
		}
		var r Remark
		r.ContentType = ct
		r.ViewTag = data[1]
		copy(r.Nonce[:], data[2:14])
		r.Content = data[14:]
		return &r, nil

	case ContentTypeChannelCreate:
		var r Remark
		r.ContentType = ct
		r.Content = data[1:]
		return &r, nil

	case ContentTypeChannel:
		if len(data) < 19 {
			return nil, ErrInsufficientData
		}
		ref := decodeBlockRef(data[1:7])
		var r Remark
		r.ContentType = ct
		binary.LittleEndian.PutUint32(r.Recipient[0:4], ref.Block)
		binary.LittleEndian.PutUint16(r.Recipient[4:6], ref.Index)
		r.Content = data[7:]
		return &r, nil

	case ContentTypeGroup:
		if len(data) < 45 {
			return nil, ErrInsufficientData
		}
		var r Remark
		r.ContentType = ct
		copy(r.Nonce[:], data[1:13])
		r.Content = data[13:]
		return &r, nil

	default:
		return nil, errReserved(byte(ct))
	}
}

func EncodeThreadContent(thread, replyTo, continues BlockRef, body []byte) []byte {
	out := make([]byte, ThreadHeaderSize, ThreadHeaderSize+len(body))
	encodeBlockRef(out[0:6], thread)
	encodeBlockRef(out[6:12], replyTo)
	encodeBlockRef(out[12:18], continues)
	out = append(out, body...)
	return out
}

func DecodeThreadContent(content []byte) (thread, replyTo, continues BlockRef, body []byte, err error) {
	if len(content) < ThreadHeaderSize {
		return BlockRef{}, BlockRef{}, BlockRef{}, nil, ErrInsufficientData
	}
	return decodeBlockRef(content[0:6]), decodeBlockRef(content[6:12]), decodeBlockRef(content[12:18]), content[18:], nil
}

func EncodeChannelContent(replyTo, continues BlockRef, body []byte) []byte {
	out := make([]byte, ChannelHeaderSize, ChannelHeaderSize+len(body))
	encodeBlockRef(out[0:6], replyTo)
	encodeBlockRef(out[6:12], continues)
	out = append(out, body...)
	return out
}

func DecodeChannelContent(content []byte) (replyTo, continues BlockRef, body []byte, err error) {
	if len(content) < ChannelHeaderSize {
		return BlockRef{}, BlockRef{}, nil, ErrInsufficientData
	}
	return decodeBlockRef(content[0:6]), decodeBlockRef(content[6:12]), content[12:], nil
}

func DecodeChannelCreate(data []byte) (name, description string, err error) {
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
	name = string(data[1 : 1+nameLen])
	descOff := 1 + nameLen
	descLen := int(data[descOff])
	if descLen > ChannelDescMax {
		return "", "", ErrInvalidChannelDesc
	}
	if len(data) < descOff+1+descLen {
		return "", "", ErrInsufficientData
	}
	description = string(data[descOff+1 : descOff+1+descLen])
	return name, description, nil
}

func EncodeGroup(nonce [12]byte, ephPubkey [32]byte, capsules []byte, ciphertext []byte) []byte {
	out := make([]byte, 0, 45+len(capsules)+len(ciphertext))
	out = append(out, ContentTypeGroup.Byte())
	out = append(out, nonce[:]...)
	out = append(out, ephPubkey[:]...)
	out = append(out, capsules...)
	out = append(out, ciphertext...)
	return out
}

func DecodeGroupContent(content []byte) (groupRef, replyTo, continues BlockRef, body []byte, err error) {
	if len(content) < ThreadHeaderSize {
		return BlockRef{}, BlockRef{}, BlockRef{}, nil, ErrInsufficientData
	}
	return decodeBlockRef(content[0:6]), decodeBlockRef(content[6:12]), decodeBlockRef(content[12:18]), content[18:], nil
}

func EncodeGroupMembers(memberPubkeys [][]byte) []byte {
	out := []byte{byte(len(memberPubkeys))}
	for _, pk := range memberPubkeys {
		out = append(out, pk...)
	}
	return out
}

func DecodeGroupMembers(data []byte) (members [][]byte, body []byte, err error) {
	if len(data) < 1 {
		return nil, nil, ErrInsufficientData
	}
	count := int(data[0])
	expected := 1 + count*32
	if len(data) < expected {
		return nil, nil, ErrInsufficientData
	}
	members = make([][]byte, count)
	for i := 0; i < count; i++ {
		pk := make([]byte, 32)
		copy(pk, data[1+i*32:1+(i+1)*32])
		members[i] = pk
	}
	return members, data[expected:], nil
}

func ChannelRefFromRecipient(recipient [32]byte) BlockRef {
	return BlockRef{
		Block: binary.LittleEndian.Uint32(recipient[0:4]),
		Index: binary.LittleEndian.Uint16(recipient[4:6]),
	}
}
