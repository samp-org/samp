package samp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
