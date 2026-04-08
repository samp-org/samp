package samp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const EncryptedOverhead = 80

var (
	ErrDecryptionFailed = errors.New("samp: decryption failed")
	ErrInvalidPoint     = errors.New("samp: invalid ristretto255 point")
)

func Sr25519SigningScalar(seed [32]byte) *ristretto255.Scalar {
	h := sha512.Sum512(seed[:])
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	divideScalarByCofactor(h[:32])
	s := ristretto255.NewScalar()
	if err := s.Decode(h[:32]); err != nil {
		var wide [64]byte
		copy(wide[:32], h[:32])
		return new(ristretto255.Scalar).FromUniformBytes(wide[:])
	}
	return s
}

func divideScalarByCofactor(s []byte) {
	var low byte
	for i := len(s) - 1; i >= 0; i-- {
		r := s[i] & 0x07
		s[i] >>= 3
		s[i] += low
		low = r << 5
	}
}

func PublicFromSeed(seed [32]byte) []byte {
	scalar := Sr25519SigningScalar(seed)
	pub := new(ristretto255.Element).ScalarBaseMult(scalar)
	return pub.Encode(nil)
}

func hkdfExpand(ikm, salt, info []byte, length int) []byte {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	io.ReadFull(r, out)
	return out
}

func deriveEphemeral(seed *[32]byte, recipient []byte, nonce *[12]byte) []byte {
	info := make([]byte, 44)
	copy(info[:32], recipient)
	copy(info[32:], nonce[:])
	return hkdfExpand(seed[:], nil, info, 32)
}

func deriveSealKey(seed *[32]byte, nonce *[12]byte) []byte {
	return hkdfExpand(seed[:], nonce[:], []byte("samp-seal"), 32)
}

func deriveSymmetricKey(sharedSecret, nonce []byte) []byte {
	return hkdfExpand(sharedSecret, nonce, []byte("samp-message"), 32)
}

func deriveViewTag(sharedSecret []byte) byte {
	out := hkdfExpand(sharedSecret, nil, []byte("samp-view-tag"), 1)
	return out[0]
}

func ecdhSharedSecret(scalar *ristretto255.Scalar, pointBytes []byte) ([]byte, error) {
	p := new(ristretto255.Element)
	if err := p.Decode(pointBytes); err != nil {
		return nil, ErrInvalidPoint
	}
	shared := new(ristretto255.Element).ScalarMult(scalar, p)
	return shared.Encode(nil), nil
}

func scalarFromBytes(b []byte) *ristretto255.Scalar {
	var wide [64]byte
	copy(wide[:32], b)
	return new(ristretto255.Scalar).FromUniformBytes(wide[:])
}

func Encrypt(plaintext, recipientPub []byte, nonce [12]byte, senderSeed [32]byte) ([]byte, error) {
	ephBytes := deriveEphemeral(&senderSeed, recipientPub, &nonce)
	ephScalar := scalarFromBytes(ephBytes)
	ephPubkey := new(ristretto255.Element).ScalarBaseMult(ephScalar)

	sharedSecret, err := ecdhSharedSecret(ephScalar, recipientPub)
	if err != nil {
		return nil, err
	}

	sealKey := deriveSealKey(&senderSeed, &nonce)
	var sealedTo [32]byte
	for i := 0; i < 32; i++ {
		sealedTo[i] = recipientPub[i] ^ sealKey[i]
	}

	symKey := deriveSymmetricKey(sharedSecret, nonce[:])
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return nil, err
	}
	ciphertextWithTag := aead.Seal(nil, nonce[:], plaintext, sealedTo[:])

	out := make([]byte, 0, EncryptedOverhead+len(plaintext))
	out = append(out, ephPubkey.Encode(nil)...)
	out = append(out, sealedTo[:]...)
	out = append(out, ciphertextWithTag...)
	return out, nil
}

func Decrypt(remark *Remark, signingScalar *ristretto255.Scalar) ([]byte, error) {
	if len(remark.Content) < EncryptedOverhead {
		return nil, ErrInsufficientData
	}
	content := remark.Content
	sharedSecret, err := ecdhSharedSecret(signingScalar, content[:32])
	if err != nil {
		return nil, err
	}
	symKey := deriveSymmetricKey(sharedSecret, remark.Nonce[:])
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, remark.Nonce[:], content[64:], content[32:64])
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func DecryptAsSender(remark *Remark, senderSeed [32]byte) ([]byte, error) {
	if len(remark.Content) < EncryptedOverhead {
		return nil, ErrInsufficientData
	}
	content := remark.Content
	nonce := remark.Nonce
	sealKey := deriveSealKey(&senderSeed, &nonce)
	var recipient [32]byte
	for i := 0; i < 32; i++ {
		recipient[i] = content[32+i] ^ sealKey[i]
	}

	ephBytes := deriveEphemeral(&senderSeed, recipient[:], &nonce)
	ephScalar := scalarFromBytes(ephBytes)
	sharedSecret, err := ecdhSharedSecret(ephScalar, recipient[:])
	if err != nil {
		return nil, err
	}

	symKey := deriveSymmetricKey(sharedSecret, nonce[:])
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce[:], content[64:], content[32:64])
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func CheckViewTag(remark *Remark, signingScalar *ristretto255.Scalar) (byte, error) {
	if len(remark.Content) < EncryptedOverhead {
		return 0, ErrInsufficientData
	}
	sharedSecret, err := ecdhSharedSecret(signingScalar, remark.Content[:32])
	if err != nil {
		return 0, err
	}
	return deriveViewTag(sharedSecret), nil
}

func UnsealRecipient(remark *Remark, senderSeed [32]byte) ([32]byte, error) {
	if len(remark.Content) < EncryptedOverhead {
		return [32]byte{}, ErrInsufficientData
	}
	nonce := remark.Nonce
	sealKey := deriveSealKey(&senderSeed, &nonce)
	var recipient [32]byte
	for i := 0; i < 32; i++ {
		recipient[i] = remark.Content[32+i] ^ sealKey[i]
	}
	return recipient, nil
}

func ComputeViewTag(senderSeed [32]byte, recipientPub []byte, nonce [12]byte) (byte, error) {
	ephBytes := deriveEphemeral(&senderSeed, recipientPub, &nonce)
	ephScalar := scalarFromBytes(ephBytes)
	sharedSecret, err := ecdhSharedSecret(ephScalar, recipientPub)
	if err != nil {
		return 0, err
	}
	return deriveViewTag(sharedSecret), nil
}

func DeriveGroupEphemeral(senderSeed, nonce []byte) []byte {
	info := make([]byte, len("samp-group-eph")+len(nonce))
	copy(info, []byte("samp-group-eph"))
	copy(info[len("samp-group-eph"):], nonce)
	return hkdfExpand(senderSeed, nil, info, 32)
}

func deriveKeyWrap(sharedSecret, nonce []byte) []byte {
	return hkdfExpand(sharedSecret, nonce, []byte("samp-key-wrap"), 32)
}

func BuildCapsules(contentKey []byte, memberPubkeys [][]byte, ephScalar, nonce []byte) []byte {
	scalar := scalarFromBytes(ephScalar)
	out := make([]byte, 0, len(memberPubkeys)*CapsuleSize)
	for _, pk := range memberPubkeys {
		shared, err := ecdhSharedSecret(scalar, pk)
		if err != nil {
			out = append(out, make([]byte, CapsuleSize)...)
			continue
		}
		tag := deriveViewTag(shared)
		kek := deriveKeyWrap(shared, nonce)
		out = append(out, tag)
		for i := 0; i < 32; i++ {
			out = append(out, contentKey[i]^kek[i])
		}
	}
	return out
}

func ScanCapsules(data, ephPubkey, myScalar, nonce []byte) (index int, contentKey []byte, found bool) {
	scalar := scalarFromBytes(myScalar)
	shared, err := ecdhSharedSecret(scalar, ephPubkey)
	if err != nil {
		return 0, nil, false
	}
	myTag := deriveViewTag(shared)
	kek := deriveKeyWrap(shared, nonce)

	offset := 0
	idx := 0
	for offset+CapsuleSize <= len(data) {
		if data[offset] == myTag {
			ck := make([]byte, 32)
			for i := 0; i < 32; i++ {
				ck[i] = data[offset+1+i] ^ kek[i]
			}
			return idx, ck, true
		}
		offset += CapsuleSize
		idx++
	}
	return 0, nil, false
}

func EncryptForGroup(plaintext []byte, memberPubkeys [][]byte, nonce, senderSeed []byte) (ephPubkey, capsules, ciphertext []byte, err error) {
	ephBytes := DeriveGroupEphemeral(senderSeed, nonce)
	ephScalar := scalarFromBytes(ephBytes)
	ephPub := new(ristretto255.Element).ScalarBaseMult(ephScalar)

	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, nil, nil, err
	}

	capsules = BuildCapsules(contentKey, memberPubkeys, ephBytes, nonce)

	aead, err := chacha20poly1305.New(contentKey)
	if err != nil {
		return nil, nil, nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)

	return ephPub.Encode(nil), capsules, ct, nil
}

func DecryptFromGroup(content, myScalar, nonce []byte, knownN int) ([]byte, error) {
	if len(content) < 32 {
		return nil, ErrInsufficientData
	}
	ephPubkey := content[:32]
	afterEph := content[32:]

	capsuleIdx, contentKey, found := ScanCapsules(afterEph, ephPubkey, myScalar, nonce)
	if !found {
		return nil, ErrDecryptionFailed
	}

	aead, err := chacha20poly1305.New(contentKey)
	if err != nil {
		return nil, err
	}

	if knownN > 0 {
		ctStart := knownN * CapsuleSize
		if ctStart > len(afterEph) {
			return nil, ErrInsufficientData
		}
		plaintext, err := aead.Open(nil, nonce, afterEph[ctStart:], nil)
		if err != nil {
			return nil, ErrDecryptionFailed
		}
		return plaintext, nil
	}

	minN := capsuleIdx + 1
	maxN := (len(afterEph) - 16) / CapsuleSize
	for n := minN; n <= maxN; n++ {
		ctStart := n * CapsuleSize
		if ctStart >= len(afterEph) {
			break
		}
		plaintext, err := aead.Open(nil, nonce, afterEph[ctStart:], nil)
		if err == nil {
			return plaintext, nil
		}
	}
	return nil, ErrDecryptionFailed
}
