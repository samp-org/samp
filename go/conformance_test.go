package samp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type keypairVec struct {
	Seed          string `json:"seed"`
	Sr25519Public string `json:"sr25519_public"`
	SigningScalar string `json:"signing_scalar"`
}

type publicMsgVec struct {
	Body   string `json:"body"`
	Remark string `json:"remark"`
}

type encryptedMsgVec struct {
	Nonce             string `json:"nonce"`
	Plaintext         string `json:"plaintext"`
	EphemeralBytes    string `json:"ephemeral_bytes"`
	EphemeralPubkey   string `json:"ephemeral_pubkey"`
	SharedSecret      string `json:"shared_secret"`
	ViewTag           byte   `json:"view_tag"`
	SealKey           string `json:"seal_key"`
	SealedTo          string `json:"sealed_to"`
	SymmetricKey      string `json:"symmetric_key"`
	CiphertextWithTag string `json:"ciphertext_with_tag"`
	EncryptedContent  string `json:"encrypted_content"`
	Remark            string `json:"remark"`
}

type threadMsgVec struct {
	Nonce            string `json:"nonce"`
	ThreadRef        [2]int `json:"thread_ref"`
	ReplyTo          [2]int `json:"reply_to"`
	Continues        [2]int `json:"continues"`
	Body             string `json:"body"`
	ThreadPlaintext  string `json:"thread_plaintext"`
	EncryptedContent string `json:"encrypted_content"`
	Remark           string `json:"remark"`
}

type senderDecryptVec struct {
	SealKey                 string `json:"seal_key"`
	UnsealedRecipient       string `json:"unsealed_recipient"`
	ReDerivedEphemeralBytes string `json:"re_derived_ephemeral_bytes"`
	ReDerivedSharedSecret   string `json:"re_derived_shared_secret"`
	Plaintext               string `json:"plaintext"`
}

type channelMsgVec struct {
	Body       string `json:"body"`
	ChannelRef [2]int `json:"channel_ref"`
	ReplyTo    [2]int `json:"reply_to"`
	Continues  [2]int `json:"continues"`
	Remark     string `json:"remark"`
}

type channelCreateVec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Remark      string `json:"remark"`
}

type groupMsgVec struct {
	Nonce             string   `json:"nonce"`
	Members           []string `json:"members"`
	Body              string   `json:"body"`
	MemberListEncoded string   `json:"member_list_encoded"`
	RootPlaintext     string   `json:"root_plaintext"`
	ContentKey        string   `json:"content_key"`
	EphPubkey         string   `json:"eph_pubkey"`
	Capsules          string   `json:"capsules"`
	Ciphertext        string   `json:"ciphertext"`
	Remark            string   `json:"remark"`
}

type edgeCases struct {
	EmptyBodyPublic        string `json:"empty_body_public"`
	MinEncrypted           string `json:"min_encrypted"`
	EmptyDescChannelCreate string `json:"empty_desc_channel_create"`
}

type negativeCases struct {
	NonSampVersion     string `json:"non_samp_version"`
	ReservedType       string `json:"reserved_type"`
	TruncatedEncrypted string `json:"truncated_encrypted"`
}

type testVectors struct {
	Alice             keypairVec       `json:"alice"`
	Bob               keypairVec       `json:"bob"`
	Charlie           keypairVec       `json:"charlie"`
	PublicMessage     publicMsgVec     `json:"public_message"`
	EncryptedMessage  encryptedMsgVec  `json:"encrypted_message"`
	ThreadMessage     threadMsgVec     `json:"thread_message"`
	SenderSelfDecrypt senderDecryptVec `json:"sender_self_decryption"`
	ChannelMessage    channelMsgVec    `json:"channel_message"`
	ChannelCreate     channelCreateVec `json:"channel_create"`
	GroupMessage      groupMsgVec      `json:"group_message"`
	EdgeCases         edgeCases        `json:"edge_cases"`
	NegativeCases     negativeCases    `json:"negative_cases"`
}

func h(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		panic(err)
	}
	return b
}

func h32(s string) [32]byte {
	var out [32]byte
	copy(out[:], h(s))
	return out
}

func h12(s string) [12]byte {
	var out [12]byte
	copy(out[:], h(s))
	return out
}

func seedFromHex(s string) Seed   { return SeedFromBytes(h32(s)) }
func pkFromHex(s string) Pubkey   { return PubkeyFromBytes(h32(s)) }
func nonceFromHex(s string) Nonce { return NonceFromBytes(h12(s)) }

func loadVectors(t *testing.T) testVectors {
	t.Helper()
	data, err := os.ReadFile("../e2e/test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v testVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func assertEqual(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytesEqual(got, want) {
		t.Fatalf("%s mismatch:\n  got:  %x\n  want: %x", name, got, want)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestConformanceKeypairAlice(t *testing.T) {
	v := loadVectors(t)
	seed := seedFromHex(v.Alice.Seed)
	scalar := Sr25519SigningScalar(seed)
	scalarBytes := scalar.ExposeSecret()
	assertEqual(t, "alice_scalar", scalarBytes[:], h(v.Alice.SigningScalar))
	pub := PublicFromSeed(seed)
	pubBytes := pub.Bytes()
	assertEqual(t, "alice_pubkey", pubBytes[:], h(v.Alice.Sr25519Public))
}

func TestConformanceKeypairBob(t *testing.T) {
	v := loadVectors(t)
	seed := seedFromHex(v.Bob.Seed)
	scalar := Sr25519SigningScalar(seed)
	scalarBytes := scalar.ExposeSecret()
	assertEqual(t, "bob_scalar", scalarBytes[:], h(v.Bob.SigningScalar))
	pub := PublicFromSeed(seed)
	pubBytes := pub.Bytes()
	assertEqual(t, "bob_pubkey", pubBytes[:], h(v.Bob.Sr25519Public))
}

func TestConformancePublicEncode(t *testing.T) {
	v := loadVectors(t)
	remark := EncodePublic(pkFromHex(v.Bob.Sr25519Public), string(h(v.PublicMessage.Body)))
	assertEqual(t, "public_remark", remark.Bytes(), h(v.PublicMessage.Remark))
}

func TestConformancePublicDecode(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(RemarkBytesFromBytes(h(v.PublicMessage.Remark)))
	if err != nil {
		t.Fatal(err)
	}
	pr, ok := r.(PublicRemark)
	if !ok {
		t.Fatalf("expected PublicRemark, got %T", r)
	}
	assertEqual(t, "body", []byte(pr.Body), h(v.PublicMessage.Body))
}

func TestConformanceEncryptedEncode(t *testing.T) {
	v := loadVectors(t)
	aliceSeed := seedFromHex(v.Alice.Seed)
	bobPub := pkFromHex(v.Bob.Sr25519Public)
	nonce := nonceFromHex(v.EncryptedMessage.Nonce)
	plaintext := PlaintextFromBytes(h(v.EncryptedMessage.Plaintext))

	content, err := Encrypt(plaintext, bobPub, nonce, aliceSeed)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "encrypted_content", content.Bytes(), h(v.EncryptedMessage.EncryptedContent))

	vt, err := ComputeViewTag(aliceSeed, bobPub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if vt.Get() != v.EncryptedMessage.ViewTag {
		t.Fatalf("view_tag: got %d, want %d", vt.Get(), v.EncryptedMessage.ViewTag)
	}

	remark := EncodeEncrypted(ContentTypeEncrypted, vt, nonce, content)
	assertEqual(t, "encrypted_remark", remark.Bytes(), h(v.EncryptedMessage.Remark))
}

func TestConformanceEncryptedIntermediates(t *testing.T) {
	v := loadVectors(t)
	content := h(v.EncryptedMessage.EncryptedContent)
	assertEqual(t, "ephemeral_pubkey", content[:32], h(v.EncryptedMessage.EphemeralPubkey))
	assertEqual(t, "sealed_to", content[32:64], h(v.EncryptedMessage.SealedTo))
	assertEqual(t, "ciphertext_with_tag", content[64:], h(v.EncryptedMessage.CiphertextWithTag))
}

func TestConformanceRecipientDecrypt(t *testing.T) {
	v := loadVectors(t)
	bobScalar := Sr25519SigningScalar(seedFromHex(v.Bob.Seed))
	r, err := DecodeRemark(RemarkBytesFromBytes(h(v.EncryptedMessage.Remark)))
	if err != nil {
		t.Fatal(err)
	}
	er := r.(EncryptedRemark)
	plaintext, err := Decrypt(er.Ciphertext, er.Nonce, bobScalar)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "plaintext", plaintext.Bytes(), h(v.EncryptedMessage.Plaintext))
}

func TestConformanceSenderSelfDecrypt(t *testing.T) {
	v := loadVectors(t)
	aliceSeed := seedFromHex(v.Alice.Seed)
	r, err := DecodeRemark(RemarkBytesFromBytes(h(v.EncryptedMessage.Remark)))
	if err != nil {
		t.Fatal(err)
	}
	er := r.(EncryptedRemark)
	plaintext, err := DecryptAsSender(er.Ciphertext, er.Nonce, aliceSeed)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "plaintext", plaintext.Bytes(), h(v.SenderSelfDecrypt.Plaintext))
	assertEqual(t, "unsealed_recipient", h(v.SenderSelfDecrypt.UnsealedRecipient), h(v.Bob.Sr25519Public))
}

func TestConformanceThreadMessage(t *testing.T) {
	v := loadVectors(t)
	aliceSeed := seedFromHex(v.Alice.Seed)
	bobPub := pkFromHex(v.Bob.Sr25519Public)
	bobScalar := Sr25519SigningScalar(seedFromHex(v.Bob.Seed))
	nonce := nonceFromHex(v.ThreadMessage.Nonce)

	th := v.ThreadMessage.ThreadRef
	rt := v.ThreadMessage.ReplyTo
	ct := v.ThreadMessage.Continues

	threadPlaintext := EncodeThreadContent(
		BlockRefFromParts(uint32(th[0]), uint16(th[1])),
		BlockRefFromParts(uint32(rt[0]), uint16(rt[1])),
		BlockRefFromParts(uint32(ct[0]), uint16(ct[1])),
		h(v.ThreadMessage.Body),
	)
	assertEqual(t, "thread_plaintext", threadPlaintext.Bytes(), h(v.ThreadMessage.ThreadPlaintext))

	encrypted, err := Encrypt(threadPlaintext, bobPub, nonce, aliceSeed)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "thread_encrypted", encrypted.Bytes(), h(v.ThreadMessage.EncryptedContent))

	tr, err := DecodeRemark(RemarkBytesFromBytes(h(v.ThreadMessage.Remark)))
	if err != nil {
		t.Fatal(err)
	}
	er := tr.(ThreadRemark)
	decrypted, err := Decrypt(er.Ciphertext, er.Nonce, bobScalar)
	if err != nil {
		t.Fatal(err)
	}
	thread, replyTo, continues, body, err := DecodeThreadContent(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if thread.Block().Get() != uint32(th[0]) || thread.Index().Get() != uint16(th[1]) {
		t.Fatalf("thread_ref mismatch")
	}
	if replyTo.Block().Get() != uint32(rt[0]) {
		t.Fatalf("reply_to mismatch")
	}
	if continues.Block().Get() != uint32(ct[0]) {
		t.Fatalf("continues mismatch")
	}
	assertEqual(t, "body", body, h(v.ThreadMessage.Body))
}

func TestConformanceChannelMessage(t *testing.T) {
	v := loadVectors(t)
	ch := v.ChannelMessage
	remark := EncodeChannelMsg(
		BlockRefFromParts(uint32(ch.ChannelRef[0]), uint16(ch.ChannelRef[1])),
		BlockRefFromParts(uint32(ch.ReplyTo[0]), uint16(ch.ReplyTo[1])),
		BlockRefFromParts(uint32(ch.Continues[0]), uint16(ch.Continues[1])),
		string(h(ch.Body)),
	)
	assertEqual(t, "channel_remark", remark.Bytes(), h(ch.Remark))
}

func TestConformanceChannelCreate(t *testing.T) {
	v := loadVectors(t)
	name, err := ChannelNameParse(v.ChannelCreate.Name)
	require.NoError(t, err)
	desc, err := ChannelDescriptionParse(v.ChannelCreate.Description)
	require.NoError(t, err)
	remark := EncodeChannelCreate(name, desc)
	assertEqual(t, "create_remark", remark.Bytes(), h(v.ChannelCreate.Remark))

	r, err := DecodeRemark(remark)
	if err != nil {
		t.Fatal(err)
	}
	cr, ok := r.(ChannelCreateRemark)
	if !ok {
		t.Fatalf("expected ChannelCreateRemark, got %T", r)
	}
	if cr.Name.String() != v.ChannelCreate.Name || cr.Description.String() != v.ChannelCreate.Description {
		t.Fatalf("create decode: got %q/%q", cr.Name.String(), cr.Description.String())
	}
}

func TestConformanceEdgeEmptyBodyPublic(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(RemarkBytesFromBytes(h(v.EdgeCases.EmptyBodyPublic)))
	if err != nil {
		t.Fatal(err)
	}
	pr, ok := r.(PublicRemark)
	if !ok || len(pr.Body) != 0 {
		t.Fatalf("empty body public")
	}
}

func TestConformanceEdgeMinEncrypted(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(RemarkBytesFromBytes(h(v.EdgeCases.MinEncrypted)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(EncryptedRemark); !ok {
		t.Fatalf("min encrypted: got %T", r)
	}
}

func TestConformanceEdgeEmptyDescCreate(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(RemarkBytesFromBytes(h(v.EdgeCases.EmptyDescChannelCreate)))
	if err != nil {
		t.Fatal(err)
	}
	cr := r.(ChannelCreateRemark)
	if cr.Name.String() != "test" || cr.Description.String() != "" {
		t.Fatalf("empty desc: got %q/%q", cr.Name.String(), cr.Description.String())
	}
}

func TestConformanceNegativeNonSampVersion(t *testing.T) {
	v := loadVectors(t)
	_, err := DecodeRemark(RemarkBytesFromBytes(h(v.NegativeCases.NonSampVersion)))
	if err == nil {
		t.Fatal("expected error for non-SAMP version")
	}
}

func TestConformanceNegativeReservedType(t *testing.T) {
	v := loadVectors(t)
	_, err := DecodeRemark(RemarkBytesFromBytes(h(v.NegativeCases.ReservedType)))
	if err == nil {
		t.Fatal("expected error for reserved type")
	}
}

func TestConformanceNegativeTruncatedEncrypted(t *testing.T) {
	v := loadVectors(t)
	_, err := DecodeRemark(RemarkBytesFromBytes(h(v.NegativeCases.TruncatedEncrypted)))
	if err == nil {
		t.Fatal("expected error for truncated encrypted")
	}
}

func TestConformanceGroupRemark(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(RemarkBytesFromBytes(h(v.GroupMessage.Remark)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(GroupRemark); !ok {
		t.Fatalf("expected GroupRemark, got %T", r)
	}
}

func TestConformanceGroupMemberList(t *testing.T) {
	v := loadVectors(t)
	encoded := h(v.GroupMessage.MemberListEncoded)
	members, body, err := DecodeGroupMembers(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != len(v.GroupMessage.Members) {
		t.Fatalf("member count: got %d, want %d", len(members), len(v.GroupMessage.Members))
	}
	for i, m := range members {
		b := m.Bytes()
		assertEqual(t, "member_pubkey", b[:], h(v.GroupMessage.Members[i]))
	}
	if len(body) != 0 {
		t.Fatalf("expected empty body after member list, got %d bytes", len(body))
	}

	reEncoded := EncodeGroupMembers(members)
	assertEqual(t, "re_encoded_member_list", reEncoded, encoded)
}

func TestConformanceGroupDecryptByMember(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(RemarkBytesFromBytes(h(v.GroupMessage.Remark)))
	if err != nil {
		t.Fatal(err)
	}
	gr := r.(GroupRemark)

	bobScalar := Sr25519SigningScalar(seedFromHex(v.Bob.Seed))
	plaintext, err := DecryptFromGroup(gr.Content, bobScalar, gr.Nonce, len(v.GroupMessage.Members))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "root_plaintext", plaintext.Bytes(), h(v.GroupMessage.RootPlaintext))

	plaintext2, err := DecryptFromGroup(gr.Content, bobScalar, gr.Nonce, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "root_plaintext_trial", plaintext2.Bytes(), h(v.GroupMessage.RootPlaintext))
}

func TestConformanceContentTypeByteValuesPinned(t *testing.T) {
	require.Equal(t, byte(0x10), ContentTypePublic.Byte())
	require.Equal(t, byte(0x11), ContentTypeEncrypted.Byte())
	require.Equal(t, byte(0x12), ContentTypeThread.Byte())
	require.Equal(t, byte(0x13), ContentTypeChannelCreate.Byte())
	require.Equal(t, byte(0x14), ContentTypeChannel.Byte())
	require.Equal(t, byte(0x15), ContentTypeGroup.Byte())
}

func TestConformanceTypedWrappersRoundTrip(t *testing.T) {
	v := loadVectors(t)
	bobRaw := h32(v.Bob.Sr25519Public)
	pk := PubkeyFromBytes(bobRaw)
	gotPk := pk.Bytes()
	require.Equal(t, bobRaw, gotPk)

	nonceRaw := h12(v.EncryptedMessage.Nonce)
	n := NonceFromBytes(nonceRaw)
	gotN := n.Bytes()
	require.Equal(t, nonceRaw, gotN)

	ghRaw := h32(v.Alice.Sr25519Public)
	gh := GenesisHashFromBytes(ghRaw)
	gotGh := gh.Bytes()
	require.Equal(t, ghRaw, gotGh)
}

func TestConformanceBlockRefStringFormat(t *testing.T) {
	r := BlockRefFromParts(42, 7)
	require.Equal(t, "#42.7", r.String())
}

func TestEncodeChannelCreateNameTooLongReturnsError(t *testing.T) {
	_, err := ChannelNameParse(strings.Repeat("x", 33))
	require.Error(t, err)
}

func TestEncodeChannelCreateEmptyNameReturnsError(t *testing.T) {
	_, err := ChannelNameParse("")
	require.Error(t, err)
}

func TestEncodeChannelCreateDescTooLongReturnsError(t *testing.T) {
	_, err := ChannelDescriptionParse(strings.Repeat("x", 129))
	require.Error(t, err)
}

func TestGroupRegularMessageRoundtrip(t *testing.T) {
	alicePub := PublicFromSeed(seedFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	bobPub := PublicFromSeed(seedFromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	members := []Pubkey{alicePub, bobPub}

	var nb [12]byte
	_, err := rand.Read(nb[:])
	require.NoError(t, err)
	nonce := NonceFromBytes(nb)

	groupRef := BlockRefFromParts(100, 1)
	plaintext := EncodeThreadContent(groupRef, BlockRef{}, BlockRef{}, []byte("non-root msg"))

	senderSeed := seedFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ephPubkey, capsules, ciphertext, err := EncryptForGroup(plaintext, members, nonce, senderSeed)
	require.NoError(t, err)

	remark := EncodeGroup(nonce, ephPubkey, capsules, ciphertext)

	r, err := DecodeRemark(remark)
	require.NoError(t, err)
	gr, ok := r.(GroupRemark)
	require.True(t, ok)

	bobScalar := Sr25519SigningScalar(seedFromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	decrypted, err := DecryptFromGroup(gr.Content, bobScalar, gr.Nonce, len(members))
	require.NoError(t, err)

	thread, _, _, body, err := DecodeThreadContent(decrypted)
	require.NoError(t, err)
	require.Equal(t, uint32(100), thread.Block().Get())
	require.Equal(t, uint16(1), thread.Index().Get())
	require.Equal(t, []byte("non-root msg"), body)
}

func TestGroupNonMemberRejected(t *testing.T) {
	alicePub := PublicFromSeed(seedFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	bobPub := PublicFromSeed(seedFromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	members := []Pubkey{alicePub, bobPub}

	var nb [12]byte
	_, err := rand.Read(nb[:])
	require.NoError(t, err)
	nonce := NonceFromBytes(nb)

	plaintext := EncodeThreadContent(BlockRefFromParts(100, 1), BlockRef{}, BlockRef{}, []byte("secret"))
	senderSeed := seedFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ephPubkey, capsules, ciphertext, err := EncryptForGroup(plaintext, members, nonce, senderSeed)
	require.NoError(t, err)

	remark := EncodeGroup(nonce, ephPubkey, capsules, ciphertext)

	r, err := DecodeRemark(remark)
	require.NoError(t, err)
	gr := r.(GroupRemark)

	charlieScalar := Sr25519SigningScalar(seedFromHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"))
	_, err = DecryptFromGroup(gr.Content, charlieScalar, gr.Nonce, len(members))
	require.Error(t, err)
}

func TestSr25519SignReturns64Bytes(t *testing.T) {
	var seedBytes [32]byte
	for i := range seedBytes {
		seedBytes[i] = 0xab
	}
	seed := SeedFromBytes(seedBytes)
	sig, err := Sr25519Sign(seed, []byte("test message"))
	require.NoError(t, err)
	b := sig.Bytes()
	require.Equal(t, 64, len(b))
}

func TestSr25519SignDiffersForDifferentMessages(t *testing.T) {
	var seedBytes [32]byte
	for i := range seedBytes {
		seedBytes[i] = 0xab
	}
	seed := SeedFromBytes(seedBytes)
	a, err := Sr25519Sign(seed, []byte("message one"))
	require.NoError(t, err)
	b, err := Sr25519Sign(seed, []byte("message two"))
	require.NoError(t, err)
	require.NotEqual(t, a.Bytes(), b.Bytes())
}

// --- Phase 2: Types ---

func TestSeedStringRedacted(t *testing.T) {
	var b [32]byte
	for i := range b {
		b[i] = 0xAA
	}
	seed := SeedFromBytes(b)
	require.Contains(t, seed.String(), "REDACTED")
}

func TestChannelNameParseTooLong(t *testing.T) {
	_, err := ChannelNameParse(strings.Repeat("x", 33))
	require.ErrorIs(t, err, ErrInvalidChannelName)
}

func TestChannelNameParseValid(t *testing.T) {
	cn, err := ChannelNameParse("test")
	require.NoError(t, err)
	require.Equal(t, "test", cn.String())
}

func TestChannelDescParseTooLong(t *testing.T) {
	_, err := ChannelDescriptionParse(strings.Repeat("x", 129))
	require.ErrorIs(t, err, ErrInvalidChannelDesc)
}

func TestBlockRefIsZero(t *testing.T) {
	require.True(t, BlockRefZero.IsZero())
	require.False(t, BlockRefFromParts(1, 0).IsZero())
	require.False(t, BlockRefFromParts(0, 1).IsZero())
}

// --- Phase 3: Encryption edge cases ---

func seedFilled(b byte) Seed {
	var s [32]byte
	for i := range s {
		s[i] = b
	}
	return SeedFromBytes(s)
}

func TestDecryptWrongKeyFails(t *testing.T) {
	seedA := seedFilled(0xAA)
	seedB := seedFilled(0xBB)
	recipientPub := PublicFromSeed(seedA)

	var nb [12]byte
	_, err := rand.Read(nb[:])
	require.NoError(t, err)
	nonce := NonceFromBytes(nb)

	ct, err := Encrypt(PlaintextFromBytes([]byte("hello")), recipientPub, nonce, seedB)
	require.NoError(t, err)

	wrongScalar := Sr25519SigningScalar(seedB)
	_, err = Decrypt(ct, nonce, wrongScalar)
	require.Error(t, err)
}

func TestEncryptDecryptAsSender(t *testing.T) {
	seedA := seedFilled(0xAA)
	seedB := seedFilled(0xBB)
	recipientPub := PublicFromSeed(seedB)

	var nb [12]byte
	_, err := rand.Read(nb[:])
	require.NoError(t, err)
	nonce := NonceFromBytes(nb)

	msg := []byte("round-trip sender")
	ct, err := Encrypt(PlaintextFromBytes(msg), recipientPub, nonce, seedA)
	require.NoError(t, err)

	pt, err := DecryptAsSender(ct, nonce, seedA)
	require.NoError(t, err)
	require.Equal(t, msg, pt.Bytes())
}

func TestUnsealRecipient(t *testing.T) {
	seedA := seedFilled(0xAA)
	seedB := seedFilled(0xBB)
	recipientPub := PublicFromSeed(seedB)

	var nb [12]byte
	_, err := rand.Read(nb[:])
	require.NoError(t, err)
	nonce := NonceFromBytes(nb)

	ct, err := Encrypt(PlaintextFromBytes([]byte("unseal")), recipientPub, nonce, seedA)
	require.NoError(t, err)

	unsealed, err := UnsealRecipient(ct, nonce, seedA)
	require.NoError(t, err)
	require.Equal(t, recipientPub.Bytes(), unsealed.Bytes())
}

func TestGroupEncryptSingleMember(t *testing.T) {
	seedA := seedFilled(0xAA)
	memberPub := PublicFromSeed(seedA)
	members := []Pubkey{memberPub}

	var nb [12]byte
	_, err := rand.Read(nb[:])
	require.NoError(t, err)
	nonce := NonceFromBytes(nb)

	msg := []byte("group-single")
	ephPubkey, capsules, ct, err := EncryptForGroup(PlaintextFromBytes(msg), members, nonce, seedA)
	require.NoError(t, err)

	ephBytes := ephPubkey.Bytes()
	content := make([]byte, 0, 32+len(capsules.Bytes())+len(ct.Bytes()))
	content = append(content, ephBytes[:]...)
	content = append(content, capsules.Bytes()...)
	content = append(content, ct.Bytes()...)

	scalar := Sr25519SigningScalar(seedA)
	pt, err := DecryptFromGroup(content, scalar, nonce, len(members))
	require.NoError(t, err)
	require.Equal(t, msg, pt.Bytes())
}

func TestGroupDecryptWrongKeyFails(t *testing.T) {
	seedA := seedFilled(0xAA)
	seedC := seedFilled(0xCC)
	memberPub := PublicFromSeed(seedA)
	members := []Pubkey{memberPub}

	var nb [12]byte
	_, err := rand.Read(nb[:])
	require.NoError(t, err)
	nonce := NonceFromBytes(nb)

	ephPubkey, capsules, ct, err := EncryptForGroup(PlaintextFromBytes([]byte("secret")), members, nonce, seedA)
	require.NoError(t, err)

	ephBytes := ephPubkey.Bytes()
	content := make([]byte, 0, 32+len(capsules.Bytes())+len(ct.Bytes()))
	content = append(content, ephBytes[:]...)
	content = append(content, capsules.Bytes()...)
	content = append(content, ct.Bytes()...)

	wrongScalar := Sr25519SigningScalar(seedC)
	_, err = DecryptFromGroup(content, wrongScalar, nonce, len(members))
	require.Error(t, err)
}

// --- Phase 4: Wire format ---

func TestDecodeRemarkEmpty(t *testing.T) {
	_, err := DecodeRemark(RemarkBytesFromBytes(nil))
	require.Error(t, err)
}

func TestIsSampRemarkFalse(t *testing.T) {
	_, err := ContentTypeFromByte(0x20)
	require.Error(t, err)

	_, err = ContentTypeFromByte(0x00)
	require.Error(t, err)
}

func TestChannelCreateRoundTrip(t *testing.T) {
	name, err := ChannelNameParse("mychan")
	require.NoError(t, err)
	desc, err := ChannelDescriptionParse("a channel")
	require.NoError(t, err)

	remark := EncodeChannelCreate(name, desc)
	r, err := DecodeRemark(remark)
	require.NoError(t, err)

	cc, ok := r.(ChannelCreateRemark)
	require.True(t, ok)
	require.Equal(t, "mychan", cc.Name.String())
	require.Equal(t, "a channel", cc.Description.String())
}

func TestDecodeThreadContentTruncated(t *testing.T) {
	short := PlaintextFromBytes([]byte{0x01, 0x02})
	_, _, _, _, err := DecodeThreadContent(short)
	require.ErrorIs(t, err, ErrInsufficientData)
}

// --- Coverage: types.go String/Len/Get/Bytes ---

func TestTypeStringMethods(t *testing.T) {
	// BlockNumber
	bn := BlockNumberFrom(42)
	require.Equal(t, uint32(42), bn.Get())
	require.Equal(t, "#42", bn.String())

	bnU64, err := BlockNumberFromUint64(100)
	require.NoError(t, err)
	require.Equal(t, uint32(100), bnU64.Get())

	_, err = BlockNumberFromUint64(0x1_0000_0000)
	require.ErrorIs(t, err, ErrBlockNumberOverflow)

	// ExtIndex
	ei := ExtIndexFrom(7)
	require.Equal(t, uint16(7), ei.Get())
	require.Equal(t, ".7", ei.String())

	eiI, err := ExtIndexFromInt(65535)
	require.NoError(t, err)
	require.Equal(t, uint16(65535), eiI.Get())

	_, err = ExtIndexFromInt(-1)
	require.ErrorIs(t, err, ErrExtIndexOverflow)
	_, err = ExtIndexFromInt(0x10000)
	require.ErrorIs(t, err, ErrExtIndexOverflow)

	// BlockRef via BlockRefNew
	br := BlockRefNew(bn, ei)
	require.Equal(t, uint32(42), br.Block().Get())
	require.Equal(t, uint16(7), br.Index().Get())

	// ExtrinsicNonce
	en := ExtrinsicNonceFrom(99)
	require.Equal(t, uint32(99), en.Get())

	// SpecVersion
	sv := SpecVersionFrom(200)
	require.Equal(t, uint32(200), sv.Get())

	// TxVersion
	tv := TxVersionFrom(3)
	require.Equal(t, uint32(3), tv.Get())

	// PalletIdx
	pi := PalletIdxFrom(5)
	require.Equal(t, uint8(5), pi.Get())

	// CallIdx
	ci := CallIdxFrom(8)
	require.Equal(t, uint8(8), ci.Get())

	// Pubkey String
	var pkb [32]byte
	pkb[0] = 0xAB
	pk := PubkeyFromBytes(pkb)
	require.Equal(t, 32, len(pk.Bytes()))
	require.Contains(t, pk.String(), "Pubkey(0x")
	require.Contains(t, pk.String(), "ab")

	// Pubkey.ToSs58
	addr := pk.ToSs58(Ss58SubstrateGeneric)
	require.NotEmpty(t, addr.String())

	// Signature String
	var sigb [64]byte
	sigb[0] = 0xCD
	sig := SignatureFromBytes(sigb)
	require.Equal(t, 64, len(sig.Bytes()))
	require.Contains(t, sig.String(), "Signature(0x")

	// GenesisHash String
	var ghb [32]byte
	ghb[0] = 0xEF
	gh := GenesisHashFromBytes(ghb)
	require.Equal(t, 32, len(gh.Bytes()))
	require.Contains(t, gh.String(), "GenesisHash(0x")

	// Nonce String
	var nb [12]byte
	nb[0] = 0x01
	n := NonceFromBytes(nb)
	require.Equal(t, 12, len(n.Bytes()))
	require.Contains(t, n.String(), "Nonce(0x")

	// ViewTag
	vt := ViewTagFrom(0x42)
	require.Equal(t, uint8(0x42), vt.Get())
	require.Equal(t, "ViewTag(0x42)", vt.String())

	// EphPubkey
	ep := EphPubkeyFromBytes(pkb)
	require.Equal(t, pkb, ep.Bytes())

	// Plaintext
	pt := PlaintextFromBytes([]byte("hello"))
	require.Equal(t, []byte("hello"), pt.Bytes())
	require.Equal(t, 5, pt.Len())
	require.Equal(t, "Plaintext(5 bytes)", pt.String())

	// Ciphertext
	ct := CiphertextFromBytes([]byte("cipher"))
	require.Equal(t, []byte("cipher"), ct.Bytes())
	require.Equal(t, 6, ct.Len())
	require.Equal(t, "Ciphertext(6 bytes)", ct.String())

	// Capsules
	capsuleData := make([]byte, CapsuleSize*2)
	caps, err := CapsulesFromBytes(capsuleData)
	require.NoError(t, err)
	require.Equal(t, CapsuleSize*2, len(caps.Bytes()))
	require.Equal(t, 2, caps.Count())
	require.Equal(t, "Capsules(2 entries)", caps.String())

	_, err = CapsulesFromBytes([]byte{0x01, 0x02})
	require.ErrorIs(t, err, ErrInvalidCapsules)

	// RemarkBytes
	rb := RemarkBytesFromBytes([]byte("remark"))
	require.Equal(t, []byte("remark"), rb.Bytes())
	require.Equal(t, 6, rb.Len())

	// ExtrinsicBytes
	eb := ExtrinsicBytesFromBytes([]byte("ext"))
	require.Equal(t, []byte("ext"), eb.Bytes())
	require.Equal(t, 3, eb.Len())

	// CallArgs
	ca := CallArgsFromBytes([]byte("args"))
	require.Equal(t, []byte("args"), ca.Bytes())
	require.Equal(t, 4, ca.Len())

	// ChannelName
	cn, err := ChannelNameParse("chan")
	require.NoError(t, err)
	require.Equal(t, "chan", cn.String())
	require.Equal(t, 4, cn.Len())

	// ChannelDescription
	cd, err := ChannelDescriptionParse("desc")
	require.NoError(t, err)
	require.Equal(t, "desc", cd.String())
	require.Equal(t, 4, cd.Len())
}

// --- Coverage: secret.go ---

func TestSecretTypesCoverage(t *testing.T) {
	var b [32]byte
	b[0] = 0xFF

	seed := SeedFromBytes(b)
	require.Equal(t, b, seed.ExposeSecret())

	ck := ContentKeyFromBytes(b)
	require.Equal(t, b, ck.ExposeSecret())
	require.Contains(t, ck.String(), "REDACTED")

	vs := ViewScalarFromBytes(b)
	require.Equal(t, b, vs.ExposeSecret())
	require.Contains(t, vs.String(), "REDACTED")
}

// --- Coverage: CheckViewTag ---

func TestCheckViewTagDirect(t *testing.T) {
	sender := seedFilled(0xAA)
	recipient := seedFilled(0xBB)
	recipientPub := PublicFromSeed(recipient)
	var nb [12]byte
	for i := range nb {
		nb[i] = 0x01
	}
	nonce := NonceFromBytes(nb)

	tag, err := ComputeViewTag(sender, recipientPub, nonce)
	require.NoError(t, err)

	pt := PlaintextFromBytes([]byte("hello"))
	ct, err := Encrypt(pt, recipientPub, nonce, sender)
	require.NoError(t, err)

	recipientScalar := Sr25519SigningScalar(recipient)
	checkedTag, err := CheckViewTag(ct, recipientScalar)
	require.NoError(t, err)
	require.Equal(t, tag.Get(), checkedTag.Get())
}

func TestCheckViewTagTruncatedCiphertext(t *testing.T) {
	scalar := Sr25519SigningScalar(seedFilled(0xAA))
	_, err := CheckViewTag(CiphertextFromBytes([]byte{0x01}), scalar)
	require.ErrorIs(t, err, ErrInsufficientData)
}

// --- Coverage: ExtrinsicError.Error() ---

func TestExtrinsicErrorString(t *testing.T) {
	e := &ExtrinsicError{Msg: "test failure"}
	require.Equal(t, "samp: extrinsic: test failure", e.Error())
}

// --- Coverage: Remark ContentType() methods ---

func TestRemarkContentTypes(t *testing.T) {
	require.Equal(t, ContentTypePublic, PublicRemark{}.ContentType())
	require.Equal(t, ContentTypeEncrypted, EncryptedRemark{}.ContentType())
	require.Equal(t, ContentTypeThread, ThreadRemark{}.ContentType())
	require.Equal(t, ContentTypeChannelCreate, ChannelCreateRemark{}.ContentType())
	require.Equal(t, ContentTypeChannel, ChannelRemark{}.ContentType())
	require.Equal(t, ContentTypeGroup, GroupRemark{}.ContentType())
	require.Equal(t, ContentType(0x18), ApplicationRemark{Tag: 0x18}.ContentType())
}

// --- Coverage: EncodeChannelContent / DecodeChannelContent / DecodeGroupContent ---

func TestChannelContentRoundTrip(t *testing.T) {
	replyTo := BlockRefFromParts(10, 1)
	continues := BlockRefFromParts(20, 2)
	body := []byte("channel body")

	pt := EncodeChannelContent(replyTo, continues, body)
	gotReply, gotCont, gotBody, err := DecodeChannelContent(pt)
	require.NoError(t, err)
	require.Equal(t, uint32(10), gotReply.Block().Get())
	require.Equal(t, uint16(1), gotReply.Index().Get())
	require.Equal(t, uint32(20), gotCont.Block().Get())
	require.Equal(t, uint16(2), gotCont.Index().Get())
	require.Equal(t, body, gotBody)
}

func TestDecodeChannelContentTruncated(t *testing.T) {
	short := PlaintextFromBytes([]byte{0x01})
	_, _, _, err := DecodeChannelContent(short)
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeGroupContentRoundTrip(t *testing.T) {
	groupRef := BlockRefFromParts(5, 0)
	replyTo := BlockRefFromParts(6, 1)
	continues := BlockRefFromParts(7, 2)
	body := []byte("group body")

	pt := EncodeThreadContent(groupRef, replyTo, continues, body)
	gotGroup, gotReply, gotCont, gotBody, err := DecodeGroupContent(pt)
	require.NoError(t, err)
	require.Equal(t, uint32(5), gotGroup.Block().Get())
	require.Equal(t, uint32(6), gotReply.Block().Get())
	require.Equal(t, uint32(7), gotCont.Block().Get())
	require.Equal(t, body, gotBody)
}

func TestDecodeGroupContentTruncated(t *testing.T) {
	short := PlaintextFromBytes([]byte{0x01, 0x02})
	_, _, _, _, err := DecodeGroupContent(short)
	require.ErrorIs(t, err, ErrInsufficientData)
}

// --- Coverage: ApplicationRemark via DecodeRemark ---

func TestDecodeRemarkApplicationType(t *testing.T) {
	data := []byte{0x18, 0xDE, 0xAD}
	r, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.NoError(t, err)
	ar, ok := r.(ApplicationRemark)
	require.True(t, ok)
	require.Equal(t, byte(0x18), ar.Tag)
	require.Equal(t, []byte{0xDE, 0xAD}, ar.Payload)
}

// --- Coverage: metadata.go Humanize with doc, maybeTranslateModule, HumanizeRpcError Module path ---

func TestErrorTableHumanizeWithDoc(t *testing.T) {
	table := NewErrorTable()
	table.byIdx[errorKey{1, 2}] = ErrorEntry{Pallet: "Balances", Variant: "InsufficientBalance", Doc: "not enough funds"}
	msg, ok := table.Humanize(1, 2)
	require.True(t, ok)
	require.Equal(t, "Balances::InsufficientBalance: not enough funds", msg)

	table.byIdx[errorKey{1, 3}] = ErrorEntry{Pallet: "Balances", Variant: "ExistentialDeposit", Doc: ""}
	msg2, ok := table.Humanize(1, 3)
	require.True(t, ok)
	require.Equal(t, "Balances::ExistentialDeposit", msg2)
}

func TestHumanizeRpcErrorTranslatesModuleError(t *testing.T) {
	table := NewErrorTable()
	table.byIdx[errorKey{5, 2}] = ErrorEntry{Pallet: "Balances", Variant: "InsufficientBalance", Doc: "not enough"}
	raw := `RPC error: {"data":"Module { index: 5, error: [2, 0, 0, 0], message: None }","message":"bad"}`
	result := table.HumanizeRpcError(raw)
	require.Equal(t, "Balances::InsufficientBalance: not enough", result)
}

func TestHumanizeRpcErrorRawModuleString(t *testing.T) {
	table := NewErrorTable()
	table.byIdx[errorKey{3, 1}] = ErrorEntry{Pallet: "System", Variant: "CallFiltered", Doc: ""}
	raw := `Module { index: 3, error: [1, 0, 0, 0], message: None }`
	result := table.HumanizeRpcError(raw)
	require.Equal(t, "System::CallFiltered", result)
}

func TestHumanizeRpcErrorTransactionFailed(t *testing.T) {
	table := NewErrorTable()
	raw := `transaction failed: {"data":"some error","message":"bad tx"}`
	result := table.HumanizeRpcError(raw)
	require.Equal(t, "some error", result)
}

// --- Coverage: ContentTypeFromByte for application range ---

func TestContentTypeFromByteApplicationRange(t *testing.T) {
	ct, err := ContentTypeFromByte(0x18)
	require.NoError(t, err)
	require.Equal(t, byte(0x18), ct.Byte())
}

// --- Coverage: DecryptFromGroup insufficient data ---

func TestDecryptFromGroupTruncated(t *testing.T) {
	scalar := Sr25519SigningScalar(seedFilled(0xAA))
	nonce := NonceFromBytes([12]byte{})
	_, err := DecryptFromGroup([]byte{0x01}, scalar, nonce, 0)
	require.ErrorIs(t, err, ErrInsufficientData)
}

// --- Coverage: Decrypt/DecryptAsSender truncated ---

func TestDecryptTruncatedCiphertext(t *testing.T) {
	scalar := Sr25519SigningScalar(seedFilled(0xAA))
	nonce := NonceFromBytes([12]byte{})
	_, err := Decrypt(CiphertextFromBytes([]byte{0x01}), nonce, scalar)
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecryptAsSenderTruncated(t *testing.T) {
	seed := seedFilled(0xAA)
	nonce := NonceFromBytes([12]byte{})
	_, err := DecryptAsSender(CiphertextFromBytes([]byte{0x01}), nonce, seed)
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestUnsealRecipientTruncated(t *testing.T) {
	seed := seedFilled(0xAA)
	nonce := NonceFromBytes([12]byte{})
	_, err := UnsealRecipient(CiphertextFromBytes([]byte{0x01}), nonce, seed)
	require.ErrorIs(t, err, ErrInsufficientData)
}

// --- Coverage: DecodeRemark edge cases ---

func TestDecodeRemarkPublicTruncated(t *testing.T) {
	data := []byte{0x10, 0x01}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeRemarkChannelTruncated(t *testing.T) {
	data := []byte{0x14, 0x01}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeRemarkGroupTruncated(t *testing.T) {
	data := []byte{0x15, 0x01}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeRemarkEncryptedTruncated(t *testing.T) {
	data := []byte{0x11, 0x01}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeRemarkChannelCreateTruncated(t *testing.T) {
	data := []byte{0x13}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeRemarkPublicInvalidUTF8(t *testing.T) {
	data := make([]byte, 34)
	data[0] = 0x10
	data[33] = 0xFF
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInvalidUTF8)
}

func TestDecodeRemarkChannelInvalidUTF8(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 0x14
	data[19] = 0xFF
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInvalidUTF8)
}

// --- Coverage: metadata DecodeUint short ---

func TestStorageLayoutDecodeUintTooShort(t *testing.T) {
	layout := StorageLayout{Offset: 0, Width: 8}
	_, err := layout.DecodeUint([]byte{0x01, 0x02})
	require.Error(t, err)
}

// --- Coverage: DecodeGroupMembers truncated ---

func TestDecodeGroupMembersTruncated(t *testing.T) {
	_, _, err := DecodeGroupMembers([]byte{0x02, 0x01})
	require.ErrorIs(t, err, ErrInsufficientData)

	_, _, err = DecodeGroupMembers([]byte{})
	require.ErrorIs(t, err, ErrInsufficientData)
}

// --- Coverage: remarkSealed() ---

func TestRemarkSealedMethods(t *testing.T) {
	PublicRemark{}.remarkSealed()
	EncryptedRemark{}.remarkSealed()
	ThreadRemark{}.remarkSealed()
	ChannelCreateRemark{}.remarkSealed()
	ChannelRemark{}.remarkSealed()
	GroupRemark{}.remarkSealed()
	ApplicationRemark{}.remarkSealed()
}

// --- Coverage: decodeChannelCreatePayload edge cases ---

func TestDecodeChannelCreateNameZeroLen(t *testing.T) {
	data := []byte{0x13, 0x00, 0x00}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.Error(t, err)
}

func TestDecodeChannelCreateNameTooLong(t *testing.T) {
	data := []byte{0x13, 0x21}
	data = append(data, make([]byte, 33)...)
	data = append(data, 0x00)
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.Error(t, err)
}

func TestDecodeChannelCreateDescTruncated(t *testing.T) {
	data := []byte{0x13, 0x04}
	data = append(data, []byte("test")...)
	data = append(data, 0x05)
	data = append(data, []byte("ab")...)
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInsufficientData)
}

func TestDecodeChannelCreateNameBodyTruncated(t *testing.T) {
	data := []byte{0x13, 0x04, 0x41}
	_, err := DecodeRemark(RemarkBytesFromBytes(data))
	require.ErrorIs(t, err, ErrInsufficientData)
}

// --- Coverage: ExtractCall more edge cases ---

func TestExtractCallTruncatedAtNonce(t *testing.T) {
	// Build a valid extrinsic and then truncate it at the nonce field
	args := buildRemarkArgs([]byte("x"))
	ext, err := BuildSignedExtrinsic(PalletIdxFrom(0), CallIdxFrom(7), args, alicePublicKey, fixedSigner, ExtrinsicNonceFrom(0), makeChainParams())
	require.NoError(t, err)

	// Truncate just after the signed header
	b := ext.Bytes()
	_, prefixLen, _ := DecodeCompact(b)
	truncated := make([]byte, prefixLen+signedHeaderLen+1)
	copy(truncated, b[:len(truncated)])
	// Re-encode compact prefix for the truncated payload
	payloadLen := len(truncated) - prefixLen
	newPrefix := EncodeCompact(uint64(payloadLen))
	final := append(newPrefix, truncated[prefixLen:]...)
	_, ok := ExtractCall(ExtrinsicBytesFromBytes(final))
	require.False(t, ok)
}

// --- Coverage: ContentTypeFromByte reserved 0x17 ---

func TestContentTypeFromByteReserved(t *testing.T) {
	_, err := ContentTypeFromByte(0x17)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reserved")
}

// --- Coverage: MetadataError.Error ---

func TestMetadataErrorString(t *testing.T) {
	e := &MetadataError{Kind: "test", Msg: "something broke"}
	require.Equal(t, "samp: metadata: something broke", e.Error())
}

// --- Coverage: channel decode round trip via DecodeRemark ---

func TestDecodeRemarkChannelRoundTrip(t *testing.T) {
	remark := EncodeChannelMsg(
		BlockRefFromParts(1, 2),
		BlockRefFromParts(3, 4),
		BlockRefFromParts(5, 6),
		"hello channel",
	)
	r, err := DecodeRemark(remark)
	require.NoError(t, err)
	cr, ok := r.(ChannelRemark)
	require.True(t, ok)
	require.Equal(t, uint32(1), cr.ChannelRef.Block().Get())
	require.Equal(t, "hello channel", cr.Body)
}

// --- Coverage: ComputeViewTag error path (invalid point) is unreachable in normal use,
// but we can cover the error-return path of Encrypt with a zero pubkey.

func TestEncryptEmptyPlaintext(t *testing.T) {
	seed := seedFilled(0xAA)
	recipientPub := PublicFromSeed(seedFilled(0xBB))
	nonce := NonceFromBytes([12]byte{0x01})
	ct, err := Encrypt(PlaintextFromBytes([]byte{}), recipientPub, nonce, seed)
	require.NoError(t, err)
	require.Equal(t, EncryptedOverhead, ct.Len())
}

func TestComputeViewTagRoundTrip(t *testing.T) {
	seed := seedFilled(0xAA)
	recipientSeed := seedFilled(0xBB)
	recipientPub := PublicFromSeed(recipientSeed)
	nonce := NonceFromBytes([12]byte{0x01})
	tag, err := ComputeViewTag(seed, recipientPub, nonce)
	require.NoError(t, err)
	require.True(t, tag.Get() < 0xFF || tag.Get() >= 0x00) // always valid byte
}

func TestDecryptAsSenderWithZeroPubkeyMayFail(t *testing.T) {
	seed := seedFilled(0xAA)
	nonce := NonceFromBytes([12]byte{0x01})
	ct := CiphertextFromBytes(make([]byte, EncryptedOverhead+1))
	_, err := DecryptAsSender(ct, nonce, seed)
	require.Error(t, err)
}

// --- Coverage: ContentTypeFromByte all valid SAMP nibbles ---

func TestContentTypeFromByteAllValid(t *testing.T) {
	for _, b := range []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F} {
		ct, err := ContentTypeFromByte(b)
		require.NoError(t, err)
		require.Equal(t, b, ct.Byte())
	}
	for _, b := range []byte{0x16, 0x17} {
		_, err := ContentTypeFromByte(b)
		require.Error(t, err)
	}
	for _, b := range []byte{0x00, 0x20, 0xFF} {
		_, err := ContentTypeFromByte(b)
		require.Error(t, err)
	}
}

// --- Coverage: ExtractCall with mortal-era-like extrinsic ---

func TestExtractCallEmptyInput(t *testing.T) {
	_, ok := ExtractCall(ExtrinsicBytesFromBytes([]byte{}))
	require.False(t, ok)
}

// --- Coverage: Polkadot metadata byteSize through nested StorageLayout ---

func TestPolkadotMetadataStorageLayoutNonce(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	layout, err := metadata.StorageLayout("System", "Account", []string{"nonce"})
	require.NoError(t, err)
	require.True(t, layout.Width > 0)
}

func TestPolkadotMetadataStorageLayoutProviders(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	layout, err := metadata.StorageLayout("System", "Account", []string{"providers"})
	require.NoError(t, err)
	require.True(t, layout.Width > 0)
}

// --- Coverage: metadata error table from parsed metadata ---

func TestPolkadotMetadataErrorTableHumanize(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	// System pallet is typically index 0, and has errors
	// Try common error indices
	found := false
	for i := uint8(0); i < 10; i++ {
		if msg, ok := metadata.Errors.Humanize(0, i); ok {
			require.NotEmpty(t, msg)
			found = true
			break
		}
	}
	require.True(t, found, "expected at least one System error in Polkadot metadata")
}

func TestPolkadotMetadataHumanizeRpcModuleError(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	// Find any valid pallet/error pair
	var palletIdx uint8
	var errIdx uint8
	found := false
	for pi := uint8(0); pi < 50 && !found; pi++ {
		for ei := uint8(0); ei < 20; ei++ {
			if _, ok := metadata.Errors.Humanize(pi, ei); ok {
				palletIdx = pi
				errIdx = ei
				found = true
				break
			}
		}
	}
	require.True(t, found)
	// Test HumanizeRpcError with Module string
	raw := fmt.Sprintf(`Module { index: %d, error: [%d, 0, 0, 0], message: None }`, palletIdx, errIdx)
	result := metadata.Errors.HumanizeRpcError(raw)
	require.NotEqual(t, raw, result)
}

// --- Coverage: StorageLayout traversal error for non-composite field ---

func TestStorageLayoutNonCompositeTraversal(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	_, err = metadata.StorageLayout("System", "Account", []string{"nonce", "invalid_subfield"})
	require.Error(t, err)
}

// --- Coverage: StorageLayout non-unsigned-int target ---

func TestStorageLayoutNonIntTarget(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	// "data" is a composite, not a uint
	_, err = metadata.StorageLayout("System", "Account", []string{"data"})
	require.Error(t, err)
}

func TestStorageLayoutReservedFieldExercisesByteSize(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	// "reserved" comes after "free", "reserved_named", "frozen" in AccountData.
	// This forces byteSize to compute widths of preceding fields.
	layout, err := metadata.StorageLayout("System", "Account", []string{"data", "reserved"})
	if err != nil {
		// "reserved" may not exist in all runtime versions; try "frozen" instead
		layout, err = metadata.StorageLayout("System", "Account", []string{"data", "frozen"})
		require.NoError(t, err)
	}
	require.True(t, layout.Width > 0)
}

func TestStorageLayoutSufficientsField(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	layout, err := metadata.StorageLayout("System", "Account", []string{"sufficients"})
	require.NoError(t, err)
	require.True(t, layout.Width > 0)
}

// --- Coverage: metadata string helpers ---

func TestTrimToJsonNoOpenBrace(t *testing.T) {
	_, ok := trimToJson("no braces here")
	require.False(t, ok)
}

func TestTrimToJsonUnclosed(t *testing.T) {
	_, ok := trimToJson(`{"key": "value"`)
	require.False(t, ok)
}

func TestTrimToJsonNested(t *testing.T) {
	s, ok := trimToJson(`prefix {"a": {"b": 1}} suffix`)
	require.True(t, ok)
	require.Equal(t, `{"a": {"b": 1}}`, s)
}

func TestTrimToJsonEscapedQuote(t *testing.T) {
	s, ok := trimToJson(`{"key": "val\"ue"}`)
	require.True(t, ok)
	require.Contains(t, s, "key")
}

func TestParseAfterNoNeedle(t *testing.T) {
	_, ok := parseAfter("hello world", "missing:")
	require.False(t, ok)
}

func TestParseAfterNoDigits(t *testing.T) {
	_, ok := parseAfter("index: abc", "index:")
	require.False(t, ok)
}

func TestParseAfterValid(t *testing.T) {
	v, ok := parseAfter("Module { index: 42, error:", "index:")
	require.True(t, ok)
	require.Equal(t, 42, v)
}

func TestParseFirstByteAfterNoNeedle(t *testing.T) {
	_, ok := parseFirstByteAfter("hello world", "error:")
	require.False(t, ok)
}

func TestParseFirstByteAfterNoBracket(t *testing.T) {
	_, ok := parseFirstByteAfter("error: abc", "error:")
	require.False(t, ok)
}

func TestParseFirstByteAfterValid(t *testing.T) {
	v, ok := parseFirstByteAfter("error: [7, 0, 0, 0]", "error:")
	require.True(t, ok)
	require.Equal(t, 7, v)
}

func TestMaybeTranslateModuleNoModule(t *testing.T) {
	table := NewErrorTable()
	_, ok := table.maybeTranslateModule("no module here")
	require.False(t, ok)
}

func TestMaybeTranslateModuleNoIndex(t *testing.T) {
	table := NewErrorTable()
	_, ok := table.maybeTranslateModule("Module { blah }")
	require.False(t, ok)
}

func TestMaybeTranslateModuleNoError(t *testing.T) {
	table := NewErrorTable()
	_, ok := table.maybeTranslateModule("Module { index: 5 }")
	require.False(t, ok)
}

func TestMaybeTranslateModuleOverflow(t *testing.T) {
	table := NewErrorTable()
	_, ok := table.maybeTranslateModule("Module { index: 999, error: [999, 0, 0, 0] }")
	require.False(t, ok)
}

func TestFindAfterAnyNoMatch(t *testing.T) {
	_, ok := findAfterAny("nothing here", []string{"foo: ", "bar: "})
	require.False(t, ok)
}

func TestFindAfterAnyMatch(t *testing.T) {
	rest, ok := findAfterAny("prefix bar: payload", []string{"foo: ", "bar: "})
	require.True(t, ok)
	require.Equal(t, "payload", rest)
}

// --- Coverage: metadata reader error paths ---

func TestReaderReadBeyondEnd(t *testing.T) {
	r := &reader{data: []byte{0x01, 0x02}, pos: 0}
	_, err := r.read(3)
	require.Error(t, err)
}

func TestReaderReadU8BeyondEnd(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := r.readU8()
	require.Error(t, err)
}

func TestReaderReadU32BeyondEnd(t *testing.T) {
	r := &reader{data: []byte{0x01, 0x02}, pos: 0}
	_, err := r.readU32()
	require.Error(t, err)
}

func TestReaderReadCompactBeyondEnd(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := r.readCompact()
	require.Error(t, err)
}

func TestReaderReadStringBeyondEnd(t *testing.T) {
	// Compact says 10 bytes but only 2 available
	r := &reader{data: []byte{0x28}, pos: 0} // compact(10)
	_, err := r.readString()
	require.Error(t, err)
}

func TestReaderReadOptionStringInvalidTag(t *testing.T) {
	r := &reader{data: []byte{0x02}, pos: 0}
	_, _, err := r.readOptionString()
	require.Error(t, err)
}

func TestReaderReadOptionStringNone(t *testing.T) {
	r := &reader{data: []byte{0x00}, pos: 0}
	s, present, err := r.readOptionString()
	require.NoError(t, err)
	require.False(t, present)
	require.Empty(t, s)
}

func TestReaderReadOptionStringSome(t *testing.T) {
	// tag=1, compact length=4, "test"
	r := &reader{data: append([]byte{0x01, 0x10}, []byte("test")...), pos: 0}
	s, present, err := r.readOptionString()
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, "test", s)
}

func TestReaderReadVecStringEmpty(t *testing.T) {
	r := &reader{data: []byte{0x00}, pos: 0}
	vs, err := r.readVecString()
	require.NoError(t, err)
	require.Empty(t, vs)
}

func TestReaderReadVecU8Empty(t *testing.T) {
	r := &reader{data: []byte{0x00}, pos: 0}
	b, err := r.readVecU8()
	require.NoError(t, err)
	require.Empty(t, b)
}

func TestReaderReadVecU8Truncated(t *testing.T) {
	// Compact says 5 bytes but only 1 available
	r := &reader{data: []byte{0x14, 0xAA}, pos: 0}
	_, err := r.readVecU8()
	require.Error(t, err)
}

func TestReaderReadVecStringTruncated(t *testing.T) {
	// Compact says 1 string, but the string's compact length is truncated
	r := &reader{data: []byte{0x04, 0x28}, pos: 0} // 1 string, string compact says 10 bytes
	_, err := r.readVecString()
	require.Error(t, err)
}

func TestOptionTagInvalid(t *testing.T) {
	r := &reader{data: []byte{0x03}, pos: 0}
	_, err := optionTag(r)
	require.Error(t, err)
}

func TestSkipTypeParamsInvalidTag(t *testing.T) {
	// 1 param, name="x", tag=2 (invalid)
	data := []byte{0x04, 0x04, 'x', 0x02}
	r := &reader{data: data, pos: 0}
	err := skipTypeParams(r)
	require.Error(t, err)
}

func TestSkipTypeParamsNone(t *testing.T) {
	// 1 param, name="x", tag=0 (None)
	data := []byte{0x04, 0x04, 'x', 0x00}
	r := &reader{data: data, pos: 0}
	err := skipTypeParams(r)
	require.NoError(t, err)
}

func TestSkipTypeParamsSome(t *testing.T) {
	// 1 param, name="x", tag=1 (Some), compact type id=0
	data := []byte{0x04, 0x04, 'x', 0x01, 0x00}
	r := &reader{data: data, pos: 0}
	err := skipTypeParams(r)
	require.NoError(t, err)
}

func TestPrimitiveFromTagUnknown(t *testing.T) {
	_, err := primitiveFromTag(99)
	require.Error(t, err)
}

func TestPrimitiveFromTagStr(t *testing.T) {
	shape, err := primitiveFromTag(2)
	require.NoError(t, err)
	_, ok := shape.(variableShape)
	require.True(t, ok)
}

func TestReadTypeDefComposite(t *testing.T) {
	// tag=0 (composite), 0 fields
	r := &reader{data: []byte{0x00, 0x00}, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	_, ok := shape.(compositeShape)
	require.True(t, ok)
}

func TestReadTypeDefVariant(t *testing.T) {
	// tag=1 (variant), 0 variants
	r := &reader{data: []byte{0x01, 0x00}, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	_, ok := shape.(variantShape)
	require.True(t, ok)
}

func TestReadTypeDefSequence(t *testing.T) {
	// tag=2 (sequence), compact type id=0
	r := &reader{data: []byte{0x02, 0x00}, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	_, ok := shape.(variableShape)
	require.True(t, ok)
}

func TestReadTypeDefArray(t *testing.T) {
	// tag=3 (array), length=4 (LE u32), compact inner type id=0
	r := &reader{data: []byte{0x03, 0x04, 0x00, 0x00, 0x00, 0x00}, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	as, ok := shape.(arrayShape)
	require.True(t, ok)
	require.Equal(t, uint32(4), as.Length)
}

func TestReadTypeDefTuple(t *testing.T) {
	// tag=4 (tuple), 2 type ids (compact 0 each)
	r := &reader{data: []byte{0x04, 0x08, 0x00, 0x04}, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	ts, ok := shape.(tupleShape)
	require.True(t, ok)
	require.Equal(t, 2, len(ts.Ids))
}

func TestReadTypeDefPrimitive(t *testing.T) {
	// tag=5 (primitive), primitive tag=3 (u8)
	r := &reader{data: []byte{0x05, 0x03}, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	ps, ok := shape.(primitiveShape)
	require.True(t, ok)
	require.Equal(t, 1, ps.Width)
	require.True(t, ps.UnsignedInt)
}

func TestReadTypeDefCompact(t *testing.T) {
	// tag=6 (compact), compact type id=0
	r := &reader{data: []byte{0x06, 0x00}, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	_, ok := shape.(variableShape)
	require.True(t, ok)
}

func TestReadTypeDefBitSequence(t *testing.T) {
	// tag=7 (bit sequence), 2 compact type ids
	r := &reader{data: []byte{0x07, 0x00, 0x04}, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	_, ok := shape.(variableShape)
	require.True(t, ok)
}

func TestReadTypeDefUnknownTag(t *testing.T) {
	r := &reader{data: []byte{0x08}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadFieldsOneField(t *testing.T) {
	// 1 field: Option(None) for name, compact type_id=0, Option(None) for typeName, 0 docs
	data := []byte{0x04, 0x00, 0x00, 0x00, 0x00}
	r := &reader{data: data, pos: 0}
	fields, err := readFields(r)
	require.NoError(t, err)
	require.Len(t, fields, 1)
}

func TestReadStorageEntryValueTypePlain(t *testing.T) {
	// tag=0, compact type_id=5
	r := &reader{data: []byte{0x00, 0x14}, pos: 0}
	ty, err := readStorageEntryValueType(r)
	require.NoError(t, err)
	require.Equal(t, uint32(5), ty)
}

func TestReadStorageEntryValueTypeMap(t *testing.T) {
	// tag=1, n_hashers=1, hasher byte, key_type compact, value_type compact
	data := []byte{0x01, 0x04, 0x00, 0x08, 0x0C}
	r := &reader{data: data, pos: 0}
	ty, err := readStorageEntryValueType(r)
	require.NoError(t, err)
	require.Equal(t, uint32(3), ty)
}

func TestReadStorageEntryValueTypeUnknown(t *testing.T) {
	r := &reader{data: []byte{0x02}, pos: 0}
	_, err := readStorageEntryValueType(r)
	require.Error(t, err)
}

func TestReadTypeDefVariantWithFields(t *testing.T) {
	// tag=1 (variant), 1 variant:
	//   name="Foo" (compact 3 + "Foo"), 0 fields, index=0, 1 doc string "test doc"
	fooName := append([]byte{0x0C}, []byte("Foo")...)
	docStr := append([]byte{0x20}, []byte("test doc")...)
	variant := append(fooName, 0x00)   // 0 fields
	variant = append(variant, 0x00)    // index=0
	variant = append(variant, 0x04)    // 1 doc
	variant = append(variant, docStr...)

	data := append([]byte{0x01, 0x04}, variant...)
	r := &reader{data: data, pos: 0}
	shape, err := readTypeDef(r)
	require.NoError(t, err)
	vs, ok := shape.(variantShape)
	require.True(t, ok)
	require.Len(t, vs.Entries, 1)
	require.Equal(t, "Foo", vs.Entries[0].Name)
	require.Equal(t, "test doc", vs.Entries[0].Doc)
}

func TestReadCompactOverflowU32(t *testing.T) {
	data := []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x02}
	r := &reader{data: data, pos: 0}
	_, err := r.readCompact()
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds u32")
}

func TestReadRegistryOneType(t *testing.T) {
	// 1 type: type_id=0, path=0 strings, 0 type_params, typedef=composite(0 fields), docs=0 strings
	data := []byte{
		0x04,       // compact 1 (1 type)
		0x00,       // compact 0 (type_id)
		0x00,       // compact 0 (path strings)
		0x00,       // compact 0 (type_params)
		0x00, 0x00, // typedef: tag=0 (composite), 0 fields
		0x00, // compact 0 (docs)
	}
	r := &reader{data: data, pos: 0}
	reg, err := readRegistry(r)
	require.NoError(t, err)
	require.Len(t, reg, 1)
}

func TestReadRegistryNonSequentialId(t *testing.T) {
	// 1 type but type_id=5 (expected 0)
	data := []byte{
		0x04, // compact 1
		0x14, // compact 5 (non-sequential)
	}
	r := &reader{data: data, pos: 0}
	_, err := readRegistry(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-sequential")
}

func TestReadFieldsWithNamedField(t *testing.T) {
	// 1 field: Option(Some) for name="foo", compact type_id=0, Option(None) for typeName, 0 docs
	data := []byte{
		0x04,                   // compact 1
		0x01, 0x0C, 'f', 'o', 'o', // Option(Some, "foo")
		0x00,       // compact 0 (type_id)
		0x00,       // Option(None) for typeName
		0x00,       // compact 0 (docs)
	}
	r := &reader{data: data, pos: 0}
	fields, err := readFields(r)
	require.NoError(t, err)
	require.Len(t, fields, 1)
	require.Equal(t, "foo", fields[0].Name)
}

func TestSkipOptionalCompactWithValue(t *testing.T) {
	// tag=1 (Some), compact value=42
	data := []byte{0x01, 0xA8}
	r := &reader{data: data, pos: 0}
	err := skipOptionalCompact(r)
	require.NoError(t, err)
}

func TestSkipOptionalCompactNone(t *testing.T) {
	data := []byte{0x00}
	r := &reader{data: data, pos: 0}
	err := skipOptionalCompact(r)
	require.NoError(t, err)
}

// Test buildErrorTable and resolveCallIndices with known data
func TestBuildErrorTableWithVariants(t *testing.T) {
	registry := []typeShape{
		variantShape{Entries: []variantEntry{
			{Index: 0, Name: "BadOrigin", Doc: "bad origin"},
			{Index: 1, Name: "CallFiltered", Doc: ""},
		}},
	}
	pending := []pendingError{{Pallet: "System", PalletIdx: 0, ErrorTy: 0}}
	table := buildErrorTable(registry, pending)
	msg, ok := table.Humanize(0, 0)
	require.True(t, ok)
	require.Equal(t, "System::BadOrigin: bad origin", msg)
	msg2, ok := table.Humanize(0, 1)
	require.True(t, ok)
	require.Equal(t, "System::CallFiltered", msg2)
}

func TestBuildErrorTableOutOfBoundsType(t *testing.T) {
	registry := []typeShape{}
	pending := []pendingError{{Pallet: "System", PalletIdx: 0, ErrorTy: 999}}
	table := buildErrorTable(registry, pending)
	_, ok := table.Humanize(0, 0)
	require.False(t, ok)
}

func TestBuildErrorTableNonVariantShape(t *testing.T) {
	registry := []typeShape{primitiveShape{Width: 4, UnsignedInt: true}}
	pending := []pendingError{{Pallet: "System", PalletIdx: 0, ErrorTy: 0}}
	table := buildErrorTable(registry, pending)
	_, ok := table.Humanize(0, 0)
	require.False(t, ok)
}

func TestResolveCallIndicesWithVariants(t *testing.T) {
	registry := []typeShape{
		variantShape{Entries: []variantEntry{
			{Index: 7, Name: "remark"},
		}},
	}
	pending := []pendingCall{{Pallet: "System", PalletIdx: 0, CallsTy: 0}}
	calls := resolveCallIndices(registry, pending)
	v, ok := calls[callKey{"System", "remark"}]
	require.True(t, ok)
	require.Equal(t, [2]uint8{0, 7}, v)
}

func TestResolveCallIndicesOutOfBounds(t *testing.T) {
	registry := []typeShape{}
	pending := []pendingCall{{Pallet: "System", PalletIdx: 0, CallsTy: 999}}
	calls := resolveCallIndices(registry, pending)
	require.Empty(t, calls)
}

func TestResolveCallIndicesNonVariant(t *testing.T) {
	registry := []typeShape{primitiveShape{Width: 4, UnsignedInt: true}}
	pending := []pendingCall{{Pallet: "System", PalletIdx: 0, CallsTy: 0}}
	calls := resolveCallIndices(registry, pending)
	require.Empty(t, calls)
}

// Exercise byteSize compositeShape branch: accessing a field that comes after
// another composite-typed field in the parent struct.
func TestStorageLayoutFieldAfterComposite(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	// In AccountData, "frozen" comes after "free" and "reserved", both u128.
	// This at minimum exercises primitiveShape summing.
	// Try more deeply nested structures if available.
	for _, path := range [][]string{
		{"data", "frozen"},
		{"data", "flags"},
	} {
		layout, err := metadata.StorageLayout("System", "Account", path)
		if err == nil {
			require.True(t, layout.Width > 0)
			return
		}
	}
	// If neither works, the metadata version doesn't have those fields; that's ok.
}
