package samp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func polkadotMetadataBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "e2e", "fixtures", "polkadot_metadata_v14.scale"))
	require.NoError(t, err)
	out := make([]byte, 0, len(raw)+4)
	out = append(out, []byte("meta")...)
	out = append(out, raw...)
	return out
}

func TestFromRuntimeMetadataRejectsEmptyInput(t *testing.T) {
	_, err := MetadataFromRuntimeMetadata([]byte{})
	var mErr *MetadataError
	require.True(t, errors.As(err, &mErr))
	require.Equal(t, "scale", mErr.Kind)
}

func TestFromRuntimeMetadataRejectsWrongMagic(t *testing.T) {
	_, err := MetadataFromRuntimeMetadata([]byte{0x00, 0x00, 0x00, 0x00, 0x0e})
	require.Error(t, err)
	require.Contains(t, err.Error(), "magic")
}

func TestFromRuntimeMetadataRejectsWrongVersion(t *testing.T) {
	_, err := MetadataFromRuntimeMetadata([]byte{0x6d, 0x65, 0x74, 0x61, 0x0d})
	require.Error(t, err)
	require.Contains(t, err.Error(), "version")
}

func TestFromRuntimeMetadataRejectsTruncatedAfterMagic(t *testing.T) {
	_, err := MetadataFromRuntimeMetadata([]byte{0x6d, 0x65, 0x74, 0x61})
	require.Error(t, err)
}

func TestParsesRealPolkadotV14Metadata(t *testing.T) {
	_, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
}

func TestPolkadotMetadataResolvesSystemAccountDataFreeLayout(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	layout, err := metadata.StorageLayout("System", "Account", []string{"data", "free"})
	require.NoError(t, err)
	require.True(t, layout.Width == 8 || layout.Width == 16)
}

func TestPolkadotMetadataFindsSystemRemarkCallIndex(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	palletIdx, _, ok := metadata.FindCallIndex("System", "remark")
	require.True(t, ok)
	require.Equal(t, uint8(0), palletIdx)
}

func TestPolkadotMetadataFindsSystemRemarkWithEventCallIndex(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	_, _, ok := metadata.FindCallIndex("System", "remark_with_event")
	require.True(t, ok)
}

func TestStorageLayoutReturnsErrorForUnknownPallet(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	_, err = metadata.StorageLayout("DoesNotExist", "Foo", []string{"bar"})
	var mErr *MetadataError
	require.True(t, errors.As(err, &mErr))
	require.Equal(t, "storage_not_found", mErr.Kind)
}

func TestStorageLayoutReturnsErrorForUnknownField(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	_, err = metadata.StorageLayout("System", "Account", []string{"data", "nonexistent_field"})
	var mErr *MetadataError
	require.True(t, errors.As(err, &mErr))
	require.Equal(t, "field_not_found", mErr.Kind)
}

func TestFindCallIndexReturnsFalseForUnknownCall(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	_, _, ok := metadata.FindCallIndex("System", "definitely_not_a_call")
	require.False(t, ok)
}

func TestStorageLayoutDecodeUintRoundTrip(t *testing.T) {
	metadata, err := MetadataFromRuntimeMetadata(polkadotMetadataBytes(t))
	require.NoError(t, err)
	layout, err := metadata.StorageLayout("System", "Account", []string{"data", "free"})
	require.NoError(t, err)

	value := uint64(12345678)
	buf := make([]byte, layout.Offset+layout.Width+16)
	for i := 0; i < layout.Width; i++ {
		buf[layout.Offset+i] = byte(value >> (8 * i))
	}
	got, err := layout.DecodeUint(buf)
	require.NoError(t, err)
	require.Equal(t, value, got)
}

func TestHumanizeRpcErrorPassesThroughUnparseable(t *testing.T) {
	table := NewErrorTable()
	require.Equal(t, "not json at all", table.HumanizeRpcError("not json at all"))
}

func TestHumanizeRpcErrorExtractsDataField(t *testing.T) {
	table := NewErrorTable()
	raw := `RPC error: {"code":1010,"data":"Transaction has a bad signature","message":"Invalid"}`
	require.Equal(t, "Transaction has a bad signature", table.HumanizeRpcError(raw))
}

func TestHumanizeRpcErrorFallsBackToMessage(t *testing.T) {
	table := NewErrorTable()
	raw := `RPC error: {"code":1010,"message":"Invalid Transaction"}`
	require.Equal(t, "Invalid Transaction", table.HumanizeRpcError(raw))
}

func TestHumanizeReturnsFalseForUnknownPair(t *testing.T) {
	table := NewErrorTable()
	_, ok := table.Humanize(99, 99)
	require.False(t, ok)
}
