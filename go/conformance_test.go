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
	seed := h32(v.Alice.Seed)
	scalar := Sr25519SigningScalar(seed)
	assertEqual(t, "alice_scalar", scalar.Encode(nil), h(v.Alice.SigningScalar))
	pub := PublicFromSeed(seed)
	assertEqual(t, "alice_pubkey", pub, h(v.Alice.Sr25519Public))
}

func TestConformanceKeypairBob(t *testing.T) {
	v := loadVectors(t)
	seed := h32(v.Bob.Seed)
	scalar := Sr25519SigningScalar(seed)
	assertEqual(t, "bob_scalar", scalar.Encode(nil), h(v.Bob.SigningScalar))
	pub := PublicFromSeed(seed)
	assertEqual(t, "bob_pubkey", pub, h(v.Bob.Sr25519Public))
}

func TestConformancePublicEncode(t *testing.T) {
	v := loadVectors(t)
	remark := EncodePublic(h32(v.Bob.Sr25519Public), h(v.PublicMessage.Body))
	assertEqual(t, "public_remark", remark, h(v.PublicMessage.Remark))
}

func TestConformancePublicDecode(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(h(v.PublicMessage.Remark))
	if err != nil {
		t.Fatal(err)
	}
	if r.ContentType != ContentTypePublic {
		t.Fatalf("content type: got 0x%02x, want 0x%02x", r.ContentType, ContentTypePublic)
	}
	assertEqual(t, "body", r.Content, h(v.PublicMessage.Body))
}

func TestConformanceEncryptedEncode(t *testing.T) {
	v := loadVectors(t)
	aliceSeed := h32(v.Alice.Seed)
	bobPub := h(v.Bob.Sr25519Public)
	nonce := h12(v.EncryptedMessage.Nonce)
	plaintext := h(v.EncryptedMessage.Plaintext)

	content, err := Encrypt(plaintext, bobPub, nonce, aliceSeed)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "encrypted_content", content, h(v.EncryptedMessage.EncryptedContent))

	vt, err := ComputeViewTag(aliceSeed, bobPub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if vt != v.EncryptedMessage.ViewTag {
		t.Fatalf("view_tag: got %d, want %d", vt, v.EncryptedMessage.ViewTag)
	}

	remark := EncodeEncrypted(ContentTypeEncrypted, vt, nonce, content)
	assertEqual(t, "encrypted_remark", remark, h(v.EncryptedMessage.Remark))
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
	bobScalar := Sr25519SigningScalar(h32(v.Bob.Seed))
	r, err := DecodeRemark(h(v.EncryptedMessage.Remark))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := Decrypt(r, bobScalar)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "plaintext", plaintext, h(v.EncryptedMessage.Plaintext))
}

func TestConformanceSenderSelfDecrypt(t *testing.T) {
	v := loadVectors(t)
	aliceSeed := h32(v.Alice.Seed)
	r, err := DecodeRemark(h(v.EncryptedMessage.Remark))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptAsSender(r, aliceSeed)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "plaintext", plaintext, h(v.SenderSelfDecrypt.Plaintext))
	assertEqual(t, "unsealed_recipient", h(v.SenderSelfDecrypt.UnsealedRecipient), h(v.Bob.Sr25519Public))
}

func TestConformanceThreadMessage(t *testing.T) {
	v := loadVectors(t)
	aliceSeed := h32(v.Alice.Seed)
	bobPub := h(v.Bob.Sr25519Public)
	bobScalar := Sr25519SigningScalar(h32(v.Bob.Seed))
	nonce := h12(v.ThreadMessage.Nonce)

	th := v.ThreadMessage.ThreadRef
	rt := v.ThreadMessage.ReplyTo
	ct := v.ThreadMessage.Continues

	threadPlaintext := EncodeThreadContent(
		BlockRef{uint32(th[0]), uint16(th[1])},
		BlockRef{uint32(rt[0]), uint16(rt[1])},
		BlockRef{uint32(ct[0]), uint16(ct[1])},
		h(v.ThreadMessage.Body),
	)
	assertEqual(t, "thread_plaintext", threadPlaintext, h(v.ThreadMessage.ThreadPlaintext))

	encrypted, err := Encrypt(threadPlaintext, bobPub, nonce, aliceSeed)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "thread_encrypted", encrypted, h(v.ThreadMessage.EncryptedContent))

	tr, err := DecodeRemark(h(v.ThreadMessage.Remark))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(tr, bobScalar)
	if err != nil {
		t.Fatal(err)
	}
	thread, replyTo, continues, body, err := DecodeThreadContent(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if thread.Block != uint32(th[0]) || thread.Index != uint16(th[1]) {
		t.Fatalf("thread_ref mismatch")
	}
	if replyTo.Block != uint32(rt[0]) {
		t.Fatalf("reply_to mismatch")
	}
	if continues.Block != uint32(ct[0]) {
		t.Fatalf("continues mismatch")
	}
	assertEqual(t, "body", body, h(v.ThreadMessage.Body))
}

func TestConformanceChannelMessage(t *testing.T) {
	v := loadVectors(t)
	ch := v.ChannelMessage
	remark := EncodeChannelMsg(
		BlockRef{uint32(ch.ChannelRef[0]), uint16(ch.ChannelRef[1])},
		BlockRef{uint32(ch.ReplyTo[0]), uint16(ch.ReplyTo[1])},
		BlockRef{uint32(ch.Continues[0]), uint16(ch.Continues[1])},
		h(ch.Body),
	)
	assertEqual(t, "channel_remark", remark, h(ch.Remark))
}

func TestConformanceChannelCreate(t *testing.T) {
	v := loadVectors(t)
	remark, err := EncodeChannelCreate(v.ChannelCreate.Name, v.ChannelCreate.Description)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "create_remark", remark, h(v.ChannelCreate.Remark))

	r, err := DecodeRemark(remark)
	if err != nil {
		t.Fatal(err)
	}
	name, desc, err := DecodeChannelCreate(r.Content)
	if err != nil {
		t.Fatal(err)
	}
	if name != v.ChannelCreate.Name || desc != v.ChannelCreate.Description {
		t.Fatalf("create decode: got %q/%q", name, desc)
	}
}

func TestConformanceEdgeEmptyBodyPublic(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(h(v.EdgeCases.EmptyBodyPublic))
	if err != nil {
		t.Fatal(err)
	}
	if r.ContentType != ContentTypePublic || len(r.Content) != 0 {
		t.Fatalf("empty body public: type=0x%02x, len=%d", r.ContentType, len(r.Content))
	}
}

func TestConformanceEdgeMinEncrypted(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(h(v.EdgeCases.MinEncrypted))
	if err != nil {
		t.Fatal(err)
	}
	if r.ContentType != ContentTypeEncrypted {
		t.Fatalf("min encrypted: type=0x%02x", r.ContentType)
	}
}

func TestConformanceEdgeEmptyDescCreate(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(h(v.EdgeCases.EmptyDescChannelCreate))
	if err != nil {
		t.Fatal(err)
	}
	name, desc, err := DecodeChannelCreate(r.Content)
	if err != nil {
		t.Fatal(err)
	}
	if name != "test" || desc != "" {
		t.Fatalf("empty desc: got %q/%q", name, desc)
	}
}

func TestConformanceNegativeNonSampVersion(t *testing.T) {
	v := loadVectors(t)
	_, err := DecodeRemark(h(v.NegativeCases.NonSampVersion))
	if err == nil {
		t.Fatal("expected error for non-SAMP version")
	}
}

func TestConformanceNegativeReservedType(t *testing.T) {
	v := loadVectors(t)
	_, err := DecodeRemark(h(v.NegativeCases.ReservedType))
	if err == nil {
		t.Fatal("expected error for reserved type")
	}
}

func TestConformanceNegativeTruncatedEncrypted(t *testing.T) {
	v := loadVectors(t)
	_, err := DecodeRemark(h(v.NegativeCases.TruncatedEncrypted))
	if err == nil {
		t.Fatal("expected error for truncated encrypted")
	}
}

func TestConformanceGroupRemark(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(h(v.GroupMessage.Remark))
	if err != nil {
		t.Fatal(err)
	}
	if r.ContentType != ContentTypeGroup {
		t.Fatalf("content type: got 0x%02x, want 0x%02x", r.ContentType, ContentTypeGroup)
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
		assertEqual(t, "member_pubkey", m, h(v.GroupMessage.Members[i]))
	}
	if len(body) != 0 {
		t.Fatalf("expected empty body after member list, got %d bytes", len(body))
	}

	reEncoded := EncodeGroupMembers(members)
	assertEqual(t, "re_encoded_member_list", reEncoded, encoded)
}

func TestConformanceGroupDecryptByMember(t *testing.T) {
	v := loadVectors(t)
	r, err := DecodeRemark(h(v.GroupMessage.Remark))
	if err != nil {
		t.Fatal(err)
	}

	bobScalar := Sr25519SigningScalar(h32(v.Bob.Seed))
	plaintext, err := DecryptFromGroup(r.Content, bobScalar.Encode(nil), r.Nonce[:], len(v.GroupMessage.Members))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "root_plaintext", plaintext, h(v.GroupMessage.RootPlaintext))

	plaintext2, err := DecryptFromGroup(r.Content, bobScalar.Encode(nil), r.Nonce[:], 0)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "root_plaintext_trial", plaintext2, h(v.GroupMessage.RootPlaintext))
}

func TestEncodeChannelCreateNameTooLongReturnsError(t *testing.T) {
	name := strings.Repeat("x", 33)
	_, err := EncodeChannelCreate(name, "desc")
	require.Error(t, err)
}

func TestEncodeChannelCreateEmptyNameReturnsError(t *testing.T) {
	_, err := EncodeChannelCreate("", "desc")
	require.Error(t, err)
}

func TestEncodeChannelCreateDescTooLongReturnsError(t *testing.T) {
	desc := strings.Repeat("x", 129)
	_, err := EncodeChannelCreate("valid", desc)
	require.Error(t, err)
}

func TestGroupRegularMessageRoundtrip(t *testing.T) {
	alicePub := PublicFromSeed(h32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	bobPub := PublicFromSeed(h32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	members := [][]byte{alicePub, bobPub}

	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	groupRef := BlockRef{Block: 100, Index: 1}
	zeroRef := BlockRef{}
	plaintext := EncodeThreadContent(groupRef, zeroRef, zeroRef, []byte("non-root msg"))

	senderSeed := h("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ephPubkey, capsules, ciphertext, err := EncryptForGroup(plaintext, members, nonce, senderSeed)
	require.NoError(t, err)

	var ephArr [32]byte
	copy(ephArr[:], ephPubkey)
	var nonceArr [12]byte
	copy(nonceArr[:], nonce)
	remark := EncodeGroup(nonceArr, ephArr, capsules, ciphertext)

	r, err := DecodeRemark(remark)
	require.NoError(t, err)
	require.Equal(t, byte(ContentTypeGroup), r.ContentType)

	bobScalar := Sr25519SigningScalar(h32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	decrypted, err := DecryptFromGroup(r.Content, bobScalar.Encode(nil), r.Nonce[:], len(members))
	require.NoError(t, err)

	thread, _, _, body, err := DecodeThreadContent(decrypted)
	require.NoError(t, err)
	require.Equal(t, uint32(100), thread.Block)
	require.Equal(t, uint16(1), thread.Index)
	require.Equal(t, []byte("non-root msg"), body)
}

func TestGroupNonMemberRejected(t *testing.T) {
	alicePub := PublicFromSeed(h32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	bobPub := PublicFromSeed(h32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	members := [][]byte{alicePub, bobPub}

	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	plaintext := EncodeThreadContent(BlockRef{Block: 100, Index: 1}, BlockRef{}, BlockRef{}, []byte("secret"))
	senderSeed := h("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ephPubkey, capsules, ciphertext, err := EncryptForGroup(plaintext, members, nonce, senderSeed)
	require.NoError(t, err)

	var ephArr [32]byte
	copy(ephArr[:], ephPubkey)
	var nonceArr [12]byte
	copy(nonceArr[:], nonce)
	remark := EncodeGroup(nonceArr, ephArr, capsules, ciphertext)

	r, err := DecodeRemark(remark)
	require.NoError(t, err)

	charlieScalar := Sr25519SigningScalar(h32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"))
	_, err = DecryptFromGroup(r.Content, charlieScalar.Encode(nil), r.Nonce[:], len(members))
	require.Error(t, err)
}
