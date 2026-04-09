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

// WHY: the single crypto boundary that turns a 32-byte ViewScalar into a
// ristretto255.Scalar. Every decrypt path funnels through here.
func viewScalarToRistretto(v ViewScalar) *ristretto255.Scalar {
	raw := v.b
	s := ristretto255.NewScalar()
	if err := s.Decode(raw[:]); err == nil {
		return s
	}
	var wide [64]byte
	copy(wide[:32], raw[:])
	return new(ristretto255.Scalar).FromUniformBytes(wide[:])
}

func Sr25519SigningScalar(seed Seed) ViewScalar {
	raw := seed.b
	h := sha512.Sum512(raw[:])
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	divideScalarByCofactor(h[:32])
	s := ristretto255.NewScalar()
	if err := s.Decode(h[:32]); err != nil {
		var wide [64]byte
		copy(wide[:32], h[:32])
		s = new(ristretto255.Scalar).FromUniformBytes(wide[:])
	}
	var out [32]byte
	copy(out[:], s.Encode(nil))
	return ViewScalar{out}
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

func PublicFromSeed(seed Seed) Pubkey {
	vs := Sr25519SigningScalar(seed)
	pub := new(ristretto255.Element).ScalarBaseMult(viewScalarToRistretto(vs))
	var out [32]byte
	copy(out[:], pub.Encode(nil))
	return Pubkey{out}
}

func hkdfExpand(ikm, salt, info []byte, length int) []byte {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	io.ReadFull(r, out)
	return out
}

func deriveEphemeral(seed Seed, recipient [32]byte, nonce Nonce) []byte {
	info := make([]byte, 44)
	copy(info[:32], recipient[:])
	copy(info[32:], nonce.b[:])
	raw := seed.b
	return hkdfExpand(raw[:], nil, info, 32)
}

func deriveSealKey(seed Seed, nonce Nonce) []byte {
	raw := seed.b
	return hkdfExpand(raw[:], nonce.chachaNonce(), []byte("samp-seal"), 32)
}

func deriveSymmetricKey(sharedSecret []byte, nonce Nonce) []byte {
	return hkdfExpand(sharedSecret, nonce.chachaNonce(), []byte("samp-message"), 32)
}

func deriveViewTagByte(sharedSecret []byte) byte {
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

func Encrypt(plaintext Plaintext, recipientPub Pubkey, nonce Nonce, senderSeed Seed) (Ciphertext, error) {
	recBytes := recipientPub.b
	ephBytes := deriveEphemeral(senderSeed, recBytes, nonce)
	ephScalar := scalarFromBytes(ephBytes)
	ephPubkey := new(ristretto255.Element).ScalarBaseMult(ephScalar)

	sharedSecret, err := ecdhSharedSecret(ephScalar, recBytes[:])
	if err != nil {
		return Ciphertext{}, err
	}

	sealKey := deriveSealKey(senderSeed, nonce)
	var sealedTo [32]byte
	for i := 0; i < 32; i++ {
		sealedTo[i] = recBytes[i] ^ sealKey[i]
	}

	symKey := deriveSymmetricKey(sharedSecret, nonce)
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return Ciphertext{}, err
	}
	ciphertextWithTag := aead.Seal(nil, nonce.chachaNonce(), plaintext.b, sealedTo[:])

	out := make([]byte, 0, EncryptedOverhead+len(plaintext.b))
	out = append(out, ephPubkey.Encode(nil)...)
	out = append(out, sealedTo[:]...)
	out = append(out, ciphertextWithTag...)
	return Ciphertext{out}, nil
}

func Decrypt(ct Ciphertext, nonce Nonce, signingScalar ViewScalar) (Plaintext, error) {
	if len(ct.b) < EncryptedOverhead {
		return Plaintext{}, ErrInsufficientData
	}
	content := ct.b
	sharedSecret, err := ecdhSharedSecret(viewScalarToRistretto(signingScalar), content[:32])
	if err != nil {
		return Plaintext{}, err
	}
	symKey := deriveSymmetricKey(sharedSecret, nonce)
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return Plaintext{}, err
	}
	plaintext, err := aead.Open(nil, nonce.chachaNonce(), content[64:], content[32:64])
	if err != nil {
		return Plaintext{}, ErrDecryptionFailed
	}
	return Plaintext{plaintext}, nil
}

func DecryptAsSender(ct Ciphertext, nonce Nonce, senderSeed Seed) (Plaintext, error) {
	if len(ct.b) < EncryptedOverhead {
		return Plaintext{}, ErrInsufficientData
	}
	content := ct.b
	sealKey := deriveSealKey(senderSeed, nonce)
	var recipient [32]byte
	for i := 0; i < 32; i++ {
		recipient[i] = content[32+i] ^ sealKey[i]
	}

	ephBytes := deriveEphemeral(senderSeed, recipient, nonce)
	ephScalar := scalarFromBytes(ephBytes)
	sharedSecret, err := ecdhSharedSecret(ephScalar, recipient[:])
	if err != nil {
		return Plaintext{}, err
	}

	symKey := deriveSymmetricKey(sharedSecret, nonce)
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return Plaintext{}, err
	}
	plaintext, err := aead.Open(nil, nonce.chachaNonce(), content[64:], content[32:64])
	if err != nil {
		return Plaintext{}, ErrDecryptionFailed
	}
	return Plaintext{plaintext}, nil
}

func CheckViewTag(ct Ciphertext, signingScalar ViewScalar) (ViewTag, error) {
	if len(ct.b) < EncryptedOverhead {
		return ViewTag{}, ErrInsufficientData
	}
	sharedSecret, err := ecdhSharedSecret(viewScalarToRistretto(signingScalar), ct.b[:32])
	if err != nil {
		return ViewTag{}, err
	}
	return ViewTag{deriveViewTagByte(sharedSecret)}, nil
}

func UnsealRecipient(ct Ciphertext, nonce Nonce, senderSeed Seed) (Pubkey, error) {
	if len(ct.b) < EncryptedOverhead {
		return Pubkey{}, ErrInsufficientData
	}
	sealKey := deriveSealKey(senderSeed, nonce)
	var recipient [32]byte
	for i := 0; i < 32; i++ {
		recipient[i] = ct.b[32+i] ^ sealKey[i]
	}
	return Pubkey{recipient}, nil
}

func ComputeViewTag(senderSeed Seed, recipient Pubkey, nonce Nonce) (ViewTag, error) {
	recBytes := recipient.b
	ephBytes := deriveEphemeral(senderSeed, recBytes, nonce)
	ephScalar := scalarFromBytes(ephBytes)
	sharedSecret, err := ecdhSharedSecret(ephScalar, recBytes[:])
	if err != nil {
		return ViewTag{}, err
	}
	return ViewTag{deriveViewTagByte(sharedSecret)}, nil
}

func deriveGroupEphemeral(senderSeed Seed, nonce Nonce) []byte {
	info := make([]byte, 0, len("samp-group-eph")+12)
	info = append(info, []byte("samp-group-eph")...)
	info = append(info, nonce.b[:]...)
	raw := senderSeed.b
	return hkdfExpand(raw[:], nil, info, 32)
}

func deriveKeyWrap(sharedSecret []byte, nonce Nonce) []byte {
	return hkdfExpand(sharedSecret, nonce.chachaNonce(), []byte("samp-key-wrap"), 32)
}

func buildCapsules(contentKey ContentKey, members []Pubkey, ephScalar *ristretto255.Scalar, nonce Nonce) Capsules {
	out := make([]byte, 0, len(members)*CapsuleSize)
	ck := contentKey.b
	for _, pk := range members {
		pkb := pk.b
		shared, err := ecdhSharedSecret(ephScalar, pkb[:])
		if err != nil {
			out = append(out, make([]byte, CapsuleSize)...)
			continue
		}
		tag := deriveViewTagByte(shared)
		kek := deriveKeyWrap(shared, nonce)
		out = append(out, tag)
		for i := 0; i < 32; i++ {
			out = append(out, ck[i]^kek[i])
		}
	}
	return Capsules{out}
}

func scanCapsules(data []byte, ephPubkey EphPubkey, myScalar ViewScalar, nonce Nonce) (int, ContentKey, bool) {
	epb := ephPubkey.b
	shared, err := ecdhSharedSecret(viewScalarToRistretto(myScalar), epb[:])
	if err != nil {
		return 0, ContentKey{}, false
	}
	myTag := deriveViewTagByte(shared)
	kek := deriveKeyWrap(shared, nonce)

	offset := 0
	idx := 0
	for offset+CapsuleSize <= len(data) {
		if data[offset] == myTag {
			var ck [32]byte
			for i := 0; i < 32; i++ {
				ck[i] = data[offset+1+i] ^ kek[i]
			}
			return idx, ContentKey{ck}, true
		}
		offset += CapsuleSize
		idx++
	}
	return 0, ContentKey{}, false
}

func EncryptForGroup(plaintext Plaintext, members []Pubkey, nonce Nonce, senderSeed Seed) (EphPubkey, Capsules, Ciphertext, error) {
	ephBytes := deriveGroupEphemeral(senderSeed, nonce)
	ephScalar := scalarFromBytes(ephBytes)
	ephPub := new(ristretto255.Element).ScalarBaseMult(ephScalar)

	var ck [32]byte
	if _, err := rand.Read(ck[:]); err != nil {
		return EphPubkey{}, Capsules{}, Ciphertext{}, err
	}
	contentKey := ContentKey{ck}

	capsules := buildCapsules(contentKey, members, ephScalar, nonce)

	aead, err := chacha20poly1305.New(ck[:])
	if err != nil {
		return EphPubkey{}, Capsules{}, Ciphertext{}, err
	}
	ct := aead.Seal(nil, nonce.chachaNonce(), plaintext.b, nil)

	var ephArr [32]byte
	copy(ephArr[:], ephPub.Encode(nil))
	return EphPubkey{ephArr}, capsules, Ciphertext{ct}, nil
}

func DecryptFromGroup(content []byte, myScalar ViewScalar, nonce Nonce, knownN int) (Plaintext, error) {
	if len(content) < 32 {
		return Plaintext{}, ErrInsufficientData
	}
	var ephArr [32]byte
	copy(ephArr[:], content[:32])
	ephPubkey := EphPubkey{ephArr}
	afterEph := content[32:]

	capsuleIdx, contentKey, found := scanCapsules(afterEph, ephPubkey, myScalar, nonce)
	if !found {
		return Plaintext{}, ErrDecryptionFailed
	}
	ckRaw := contentKey.b

	aead, err := chacha20poly1305.New(ckRaw[:])
	if err != nil {
		return Plaintext{}, err
	}

	if knownN > 0 {
		ctStart := knownN * CapsuleSize
		if ctStart > len(afterEph) {
			return Plaintext{}, ErrInsufficientData
		}
		pt, err := aead.Open(nil, nonce.chachaNonce(), afterEph[ctStart:], nil)
		if err != nil {
			return Plaintext{}, ErrDecryptionFailed
		}
		return Plaintext{pt}, nil
	}

	minN := capsuleIdx + 1
	maxN := (len(afterEph) - 16) / CapsuleSize
	for n := minN; n <= maxN; n++ {
		ctStart := n * CapsuleSize
		if ctStart >= len(afterEph) {
			break
		}
		pt, err := aead.Open(nil, nonce.chachaNonce(), afterEph[ctStart:], nil)
		if err == nil {
			return Plaintext{pt}, nil
		}
	}
	return Plaintext{}, ErrDecryptionFailed
}
