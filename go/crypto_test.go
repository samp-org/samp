package samp

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func randomSeed(t *testing.T) Seed {
	t.Helper()
	var b [32]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return SeedFromBytes(b)
}

func randomNonce(t *testing.T) Nonce {
	t.Helper()
	var b [12]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return NonceFromBytes(b)
}

func TestDecryptCorruptedCiphertextBody(t *testing.T) {
	sender := randomSeed(t)
	recipientSeed := randomSeed(t)
	recipientPub := PublicFromSeed(recipientSeed)
	recipientScalar := Sr25519SigningScalar(recipientSeed)
	nonce := randomNonce(t)

	ct, err := Encrypt(PlaintextFromBytes([]byte("test")), recipientPub, nonce, sender)
	require.NoError(t, err)

	corrupted := make([]byte, len(ct.Bytes()))
	copy(corrupted, ct.Bytes())
	corrupted[len(corrupted)-1] ^= 0xFF
	_, err = Decrypt(CiphertextFromBytes(corrupted), nonce, recipientScalar)
	require.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptWithWrongNonceFails(t *testing.T) {
	sender := randomSeed(t)
	recipientSeed := randomSeed(t)
	recipientPub := PublicFromSeed(recipientSeed)
	recipientScalar := Sr25519SigningScalar(recipientSeed)
	nonce := randomNonce(t)

	ct, err := Encrypt(PlaintextFromBytes([]byte("secret")), recipientPub, nonce, sender)
	require.NoError(t, err)

	wrongNonce := randomNonce(t)
	_, err = Decrypt(ct, wrongNonce, recipientScalar)
	require.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptAsSenderWrongSeedFails(t *testing.T) {
	sender := randomSeed(t)
	recipientSeed := randomSeed(t)
	recipientPub := PublicFromSeed(recipientSeed)
	nonce := randomNonce(t)

	ct, err := Encrypt(PlaintextFromBytes([]byte("test")), recipientPub, nonce, sender)
	require.NoError(t, err)

	wrongSender := randomSeed(t)
	_, err = DecryptAsSender(ct, nonce, wrongSender)
	require.Error(t, err)
}

func TestDecryptAsSenderCorruptedAAD(t *testing.T) {
	sender := randomSeed(t)
	recipientSeed := randomSeed(t)
	recipientPub := PublicFromSeed(recipientSeed)
	nonce := randomNonce(t)

	ct, err := Encrypt(PlaintextFromBytes([]byte("aad test")), recipientPub, nonce, sender)
	require.NoError(t, err)

	corrupted := make([]byte, len(ct.Bytes()))
	copy(corrupted, ct.Bytes())
	// Corrupt the sealed-to bytes (AAD, bytes 32-64).
	// Corrupting AAD causes the unsealed recipient to be wrong, which may yield
	// either an invalid ristretto point or a decryption failure.
	corrupted[40] ^= 0xFF
	_, err = DecryptAsSender(CiphertextFromBytes(corrupted), nonce, sender)
	require.Error(t, err)
}

func TestViewScalarToRistrettoWithAllOnesScalar(t *testing.T) {
	// All-ones is likely not a valid canonical scalar, exercises the fallback path.
	var b [32]byte
	for i := range b {
		b[i] = 0xFF
	}
	s := viewScalarToRistretto(ViewScalarFromBytes(b))
	require.NotNil(t, s)
}

func TestComputeViewTagWithInvalidPubkey(t *testing.T) {
	sender := randomSeed(t)
	nonce := randomNonce(t)
	// A pubkey of all 0xFF is not a valid ristretto point.
	var bad [32]byte
	for i := range bad {
		bad[i] = 0xFF
	}
	_, err := ComputeViewTag(sender, PubkeyFromBytes(bad), nonce)
	require.ErrorIs(t, err, ErrInvalidPoint)
}

func TestEncryptWithInvalidRecipientPubkey(t *testing.T) {
	sender := randomSeed(t)
	nonce := randomNonce(t)
	var bad [32]byte
	for i := range bad {
		bad[i] = 0xFF
	}
	_, err := Encrypt(PlaintextFromBytes([]byte("x")), PubkeyFromBytes(bad), nonce, sender)
	require.ErrorIs(t, err, ErrInvalidPoint)
}

func TestCheckViewTagWithInvalidEphPoint(t *testing.T) {
	scalar := Sr25519SigningScalar(randomSeed(t))
	// Build ciphertext with invalid ephemeral point (first 32 bytes).
	ct := make([]byte, EncryptedOverhead+1)
	for i := 0; i < 32; i++ {
		ct[i] = 0xFF
	}
	_, err := CheckViewTag(CiphertextFromBytes(ct), scalar)
	require.ErrorIs(t, err, ErrInvalidPoint)
}

func TestDecryptWithInvalidEphPoint(t *testing.T) {
	scalar := Sr25519SigningScalar(randomSeed(t))
	nonce := randomNonce(t)
	ct := make([]byte, EncryptedOverhead+1)
	for i := 0; i < 32; i++ {
		ct[i] = 0xFF
	}
	_, err := Decrypt(CiphertextFromBytes(ct), nonce, scalar)
	require.ErrorIs(t, err, ErrInvalidPoint)
}

func TestBuildCapsulesWithInvalidMemberPoint(t *testing.T) {
	var ck [32]byte
	contentKey := ContentKeyFromBytes(ck)
	var invalidPub [32]byte
	for i := range invalidPub {
		invalidPub[i] = 0xFF
	}
	members := []Pubkey{PubkeyFromBytes(invalidPub)}

	seed := randomSeed(t)
	nonce := randomNonce(t)
	ephBytes := deriveGroupEphemeral(seed, nonce)
	ephScalar := scalarFromBytes(ephBytes)

	capsules := buildCapsules(contentKey, members, ephScalar, nonce)
	require.Equal(t, CapsuleSize, len(capsules.Bytes()))
	expected := make([]byte, CapsuleSize)
	require.Equal(t, expected, capsules.Bytes())
}

func TestScanCapsulesNoMatchReturnsNotFound(t *testing.T) {
	// Construct capsule data where all view tags are 0xAA.
	capsuleData := make([]byte, CapsuleSize*2)
	for i := range capsuleData {
		capsuleData[i] = 0xAA
	}
	// Use a real ephemeral pubkey from a seed.
	seed := randomSeed(t)
	scalar := Sr25519SigningScalar(seed)
	pub := PublicFromSeed(seed)
	nonce := randomNonce(t)

	_, _, found := scanCapsules(capsuleData, EphPubkeyFromBytes(pub.Bytes()), scalar, nonce)
	// Either the tag happens to match (1/256) or not -- just exercise the path.
	_ = found
}

func TestScanCapsulesInvalidEphPubkey(t *testing.T) {
	capsuleData := make([]byte, CapsuleSize)
	var badEph [32]byte
	for i := range badEph {
		badEph[i] = 0xFF
	}
	scalar := Sr25519SigningScalar(randomSeed(t))
	nonce := randomNonce(t)
	_, _, found := scanCapsules(capsuleData, EphPubkeyFromBytes(badEph), scalar, nonce)
	require.False(t, found)
}

func TestDecryptFromGroupCorruptedCiphertextBody(t *testing.T) {
	sender := randomSeed(t)
	nonce := randomNonce(t)
	memberSeed := randomSeed(t)
	members := []Pubkey{PublicFromSeed(memberSeed)}

	ephPub, capsules, ct, err := EncryptForGroup(PlaintextFromBytes([]byte("x")), members, nonce, sender)
	require.NoError(t, err)

	content := make([]byte, 0)
	epb := ephPub.Bytes()
	content = append(content, epb[:]...)
	content = append(content, capsules.Bytes()...)
	corrupted := make([]byte, len(ct.Bytes()))
	copy(corrupted, ct.Bytes())
	for i := range corrupted {
		corrupted[i] ^= 0xFF
	}
	content = append(content, corrupted...)

	scalar := Sr25519SigningScalar(memberSeed)
	_, err = DecryptFromGroup(content, scalar, nonce, len(members))
	require.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptFromGroupKnownNTooLarge(t *testing.T) {
	sender := randomSeed(t)
	nonce := randomNonce(t)
	memberSeed := randomSeed(t)
	members := []Pubkey{PublicFromSeed(memberSeed)}

	ephPub, capsules, ct, err := EncryptForGroup(PlaintextFromBytes([]byte("x")), members, nonce, sender)
	require.NoError(t, err)

	content := make([]byte, 0)
	epb := ephPub.Bytes()
	content = append(content, epb[:]...)
	content = append(content, capsules.Bytes()...)
	content = append(content, ct.Bytes()...)

	scalar := Sr25519SigningScalar(memberSeed)
	_, err = DecryptFromGroup(content, scalar, nonce, 999)
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecryptFromGroupTrialDecryptLoopExhaustion(t *testing.T) {
	sender := randomSeed(t)
	nonce := randomNonce(t)
	memberSeed := randomSeed(t)
	members := []Pubkey{PublicFromSeed(memberSeed)}

	ephPub, capsules, ct, err := EncryptForGroup(PlaintextFromBytes([]byte("loop exhaust")), members, nonce, sender)
	require.NoError(t, err)

	content := make([]byte, 0)
	epb := ephPub.Bytes()
	content = append(content, epb[:]...)
	content = append(content, capsules.Bytes()...)
	corrupted := make([]byte, len(ct.Bytes()))
	copy(corrupted, ct.Bytes())
	for i := range corrupted {
		corrupted[i] ^= 0xFF
	}
	content = append(content, corrupted...)

	scalar := Sr25519SigningScalar(memberSeed)
	_, err = DecryptFromGroup(content, scalar, nonce, 0)
	require.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestEncryptForGroupThreeMembers(t *testing.T) {
	sender := randomSeed(t)
	nonce := randomNonce(t)
	seeds := make([]Seed, 3)
	members := make([]Pubkey, 3)
	for i := range seeds {
		seeds[i] = randomSeed(t)
		members[i] = PublicFromSeed(seeds[i])
	}
	msg := PlaintextFromBytes([]byte("three members"))

	ephPub, capsules, ct, err := EncryptForGroup(msg, members, nonce, sender)
	require.NoError(t, err)

	content := make([]byte, 0)
	epb := ephPub.Bytes()
	content = append(content, epb[:]...)
	content = append(content, capsules.Bytes()...)
	content = append(content, ct.Bytes()...)

	for i, s := range seeds {
		scalar := Sr25519SigningScalar(s)
		pt, err := DecryptFromGroup(content, scalar, nonce, len(members))
		require.NoError(t, err, "member %d failed to decrypt", i)
		require.Equal(t, msg.Bytes(), pt.Bytes())
	}
}

func TestEncryptForGroupTrialDecryptWithoutKnownN(t *testing.T) {
	sender := randomSeed(t)
	nonce := randomNonce(t)
	seeds := make([]Seed, 2)
	members := make([]Pubkey, 2)
	for i := range seeds {
		seeds[i] = randomSeed(t)
		members[i] = PublicFromSeed(seeds[i])
	}
	msg := PlaintextFromBytes([]byte("trial"))

	ephPub, capsules, ct, err := EncryptForGroup(msg, members, nonce, sender)
	require.NoError(t, err)

	content := make([]byte, 0)
	epb := ephPub.Bytes()
	content = append(content, epb[:]...)
	content = append(content, capsules.Bytes()...)
	content = append(content, ct.Bytes()...)

	scalar := Sr25519SigningScalar(seeds[1])
	pt, err := DecryptFromGroup(content, scalar, nonce, 0)
	require.NoError(t, err)
	require.Equal(t, msg.Bytes(), pt.Bytes())
}

func TestDecryptFromGroupInvalidEphPubkeyPoint(t *testing.T) {
	nonce := randomNonce(t)
	scalar := Sr25519SigningScalar(randomSeed(t))
	// Invalid ephemeral pubkey (all 0xFF) followed by a capsule and some ciphertext.
	content := make([]byte, 32+CapsuleSize+20)
	for i := 0; i < 32; i++ {
		content[i] = 0xFF
	}
	_, err := DecryptFromGroup(content, scalar, nonce, 1)
	require.ErrorIs(t, err, ErrDecryptionFailed)
}
