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

const EncryptedOverhead = 80 // ephemeral(32) + sealed_to(32) + auth_tag(16)

var (
	ErrDecryptionFailed = errors.New("samp: decryption failed")
	ErrInvalidPoint     = errors.New("samp: invalid ristretto255 point")
)

// Sr25519SigningScalar derives the sr25519 signing scalar from a 32-byte seed.
// Matches schnorrkel's ExpansionMode::Ed25519: SHA-512, clamp, divide by cofactor (8).
func Sr25519SigningScalar(seed [32]byte) *ristretto255.Scalar {
	h := sha512.Sum512(seed[:])
	// Ed25519 clamping
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	// Divide by cofactor (8) = right-shift entire byte array by 3 bits.
	// schnorrkel does this to keep a clean representation mod l.
	divideScalarByCofactor(h[:32])
	// After /8 the value fits in ~251 bits, always < l. Decode as canonical scalar.
	s := ristretto255.NewScalar()
	if err := s.Decode(h[:32]); err != nil {
		// Fallback: reduce via FromUniformBytes (should not be needed)
		var wide [64]byte
		copy(wide[:32], h[:32])
		return new(ristretto255.Scalar).FromUniformBytes(wide[:])
	}
	return s
}

func divideScalarByCofactor(s []byte) {
	var low byte
	for i := len(s) - 1; i >= 0; i-- {
		r := s[i] & 0x07 // save bottom 3 bits
		s[i] >>= 3       // divide by 8
		s[i] += low
		low = r << 5
	}
}

// PublicFromSeed derives the sr25519 public key (Ristretto255 point) from a seed.
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
	return hkdfExpand(seed[:], nonce[:], []byte("samp-seal-v1"), 32)
}

func deriveSymmetricKey(sharedSecret, nonce []byte) []byte {
	return hkdfExpand(sharedSecret, nonce, []byte("samp-message-v1"), 32)
}

func deriveViewTag(sharedSecret []byte) byte {
	out := hkdfExpand(sharedSecret, nil, []byte("samp-view-tag-v1"), 1)
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

// Encrypt encrypts plaintext for a recipient.
// Returns: ephemeral(32) || sealed_to(32) || ciphertext || auth_tag(16).
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
	ciphertextWithTag := aead.Seal(nil, nonce[:], plaintext, nil)

	out := make([]byte, 0, EncryptedOverhead+len(plaintext))
	out = append(out, ephPubkey.Encode(nil)...)
	out = append(out, sealedTo[:]...)
	out = append(out, ciphertextWithTag...)
	return out, nil
}

// Decrypt decrypts as the recipient using the signing scalar.
// Content: ephemeral(32) || sealed_to(32) || ciphertext || auth_tag(16).
func Decrypt(content []byte, signingScalar *ristretto255.Scalar, nonce [12]byte) ([]byte, error) {
	if len(content) < EncryptedOverhead {
		return nil, ErrInsufficientData
	}
	sharedSecret, err := ecdhSharedSecret(signingScalar, content[:32])
	if err != nil {
		return nil, err
	}
	symKey := deriveSymmetricKey(sharedSecret, nonce[:])
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce[:], content[64:], nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// DecryptAsSender decrypts using the sender's seed (via sealed_to).
// Content: ephemeral(32) || sealed_to(32) || ciphertext || auth_tag(16).
func DecryptAsSender(content []byte, senderSeed [32]byte, nonce [12]byte) ([]byte, error) {
	if len(content) < EncryptedOverhead {
		return nil, ErrInsufficientData
	}
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
	plaintext, err := aead.Open(nil, nonce[:], content[64:], nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// CheckViewTag computes the recipient-side view tag (Section 5.3).
// Extracts eph_pubkey from encryptedContent[0..32], computes shared secret, derives tag.
func CheckViewTag(signingScalar *ristretto255.Scalar, encryptedContent []byte) (byte, error) {
	if len(encryptedContent) < EncryptedOverhead {
		return 0, ErrInsufficientData
	}
	sharedSecret, err := ecdhSharedSecret(signingScalar, encryptedContent[:32])
	if err != nil {
		return 0, err
	}
	return deriveViewTag(sharedSecret), nil
}

// UnsealRecipient recovers the recipient pubkey from sealed_to (Section 5.5 step 3).
func UnsealRecipient(encryptedContent []byte, senderSeed [32]byte, nonce [12]byte) ([32]byte, error) {
	if len(encryptedContent) < EncryptedOverhead {
		return [32]byte{}, ErrInsufficientData
	}
	sealKey := deriveSealKey(&senderSeed, &nonce)
	var recipient [32]byte
	for i := 0; i < 32; i++ {
		recipient[i] = encryptedContent[32+i] ^ sealKey[i]
	}
	return recipient, nil
}

// ComputeViewTag computes the sender-side view tag.
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
	return hkdfExpand(sharedSecret, nonce, []byte("samp-key-wrap-v1"), 32)
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
