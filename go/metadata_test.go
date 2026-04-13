package samp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestByteSizeCompositeShape(t *testing.T) {
	// Registry: [0]=u32 primitive, [1]=composite{field "a": type 0, field "b": type 0}
	m := &Metadata{
		registry: []typeShape{
			primitiveShape{Width: 4, UnsignedInt: true},
			compositeShape{Fields: []compositeField{
				{Name: "a", Type: 0},
				{Name: "b", Type: 0},
			}},
		},
	}
	size, err := m.byteSize(1)
	require.NoError(t, err)
	require.Equal(t, 8, size) // 4 + 4
}

func TestByteSizeArrayShape(t *testing.T) {
	// Registry: [0]=u8 primitive, [1]=array of type 0, length 16
	m := &Metadata{
		registry: []typeShape{
			primitiveShape{Width: 1, UnsignedInt: true},
			arrayShape{Inner: 0, Length: 16},
		},
	}
	size, err := m.byteSize(1)
	require.NoError(t, err)
	require.Equal(t, 16, size) // 1 * 16
}

func TestByteSizeTupleShape(t *testing.T) {
	// Registry: [0]=u32, [1]=u64, [2]=tuple(0, 1)
	m := &Metadata{
		registry: []typeShape{
			primitiveShape{Width: 4, UnsignedInt: true},
			primitiveShape{Width: 8, UnsignedInt: true},
			tupleShape{Ids: []uint32{0, 1}},
		},
	}
	size, err := m.byteSize(2)
	require.NoError(t, err)
	require.Equal(t, 12, size) // 4 + 8
}

func TestByteSizeVariableShapeReturnsError(t *testing.T) {
	m := &Metadata{
		registry: []typeShape{variableShape{}},
	}
	_, err := m.byteSize(0)
	require.Error(t, err)
	var mErr *MetadataError
	require.True(t, errors.As(err, &mErr))
	require.Equal(t, "variable_width", mErr.Kind)
}

func TestByteSizeOutOfBoundsTypeId(t *testing.T) {
	m := &Metadata{registry: []typeShape{}}
	_, err := m.byteSize(999)
	require.Error(t, err)
}

func TestByteSizeNestedCompositeError(t *testing.T) {
	// Composite field references a variable-width type -> error propagates.
	m := &Metadata{
		registry: []typeShape{
			variableShape{},
			compositeShape{Fields: []compositeField{
				{Name: "x", Type: 0},
			}},
		},
	}
	_, err := m.byteSize(1)
	require.Error(t, err)
}

func TestByteSizeArrayInnerError(t *testing.T) {
	m := &Metadata{
		registry: []typeShape{
			variableShape{},
			arrayShape{Inner: 0, Length: 10},
		},
	}
	_, err := m.byteSize(1)
	require.Error(t, err)
}

func TestByteSizeTupleInnerError(t *testing.T) {
	m := &Metadata{
		registry: []typeShape{
			variableShape{},
			tupleShape{Ids: []uint32{0}},
		},
	}
	_, err := m.byteSize(1)
	require.Error(t, err)
}

func TestTypeAtOutOfBounds(t *testing.T) {
	m := &Metadata{registry: []typeShape{}}
	_, err := m.typeAt(5)
	require.Error(t, err)
}

func TestIsTypeShapeMethods(t *testing.T) {
	// Exercise all isTypeShape interface methods.
	primitiveShape{}.isTypeShape()
	compositeShape{}.isTypeShape()
	arrayShape{}.isTypeShape()
	tupleShape{}.isTypeShape()
	variantShape{}.isTypeShape()
	variableShape{}.isTypeShape()
}

func TestReadTypeDefVariantTruncatedName(t *testing.T) {
	// tag=1 (variant), 1 variant, but name string is truncated
	r := &reader{data: []byte{0x01, 0x04, 0x28}, pos: 0} // 1 variant, string compact=10 but no data
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefVariantTruncatedFields(t *testing.T) {
	// tag=1, 1 variant, name="A", then truncated at fields
	data := []byte{0x01, 0x04, 0x04, 'A'}
	// readFields will read compact count; we need at least 1 more byte
	r := &reader{data: data, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefVariantTruncatedIndex(t *testing.T) {
	// tag=1, 1 variant, name="A", 0 fields, then truncated at index
	data := []byte{0x01, 0x04, 0x04, 'A', 0x00}
	r := &reader{data: data, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefVariantTruncatedDocs(t *testing.T) {
	// tag=1, 1 variant, name="A", 0 fields, index=0, then truncated at docs
	data := []byte{0x01, 0x04, 0x04, 'A', 0x00, 0x00}
	r := &reader{data: data, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefSequenceTruncated(t *testing.T) {
	// tag=2 (sequence), truncated compact
	r := &reader{data: []byte{0x02}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefArrayTruncatedLength(t *testing.T) {
	// tag=3 (array), truncated u32
	r := &reader{data: []byte{0x03, 0x01, 0x02}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefArrayTruncatedInner(t *testing.T) {
	// tag=3 (array), length=4, truncated compact inner
	r := &reader{data: []byte{0x03, 0x04, 0x00, 0x00, 0x00}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefTupleTruncatedCount(t *testing.T) {
	// tag=4, truncated compact
	r := &reader{data: []byte{0x04}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefTupleTruncatedId(t *testing.T) {
	// tag=4, 1 element, truncated id
	r := &reader{data: []byte{0x04, 0x04}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefPrimitiveTruncated(t *testing.T) {
	// tag=5, truncated primitive tag
	r := &reader{data: []byte{0x05}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefCompactTruncated(t *testing.T) {
	// tag=6, truncated compact
	r := &reader{data: []byte{0x06}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefBitSequenceTruncatedFirst(t *testing.T) {
	// tag=7, truncated first compact
	r := &reader{data: []byte{0x07}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefBitSequenceTruncatedSecond(t *testing.T) {
	// tag=7, first compact=0, truncated second compact
	r := &reader{data: []byte{0x07, 0x00}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadTypeDefEmpty(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := readTypeDef(r)
	require.Error(t, err)
}

func TestReadFieldsTruncatedOptionString(t *testing.T) {
	// 1 field, truncated at readOptionString
	r := &reader{data: []byte{0x04}, pos: 0}
	_, err := readFields(r)
	require.Error(t, err)
}

func TestReadFieldsTruncatedTypeId(t *testing.T) {
	// 1 field, Option(None) for name, truncated at type_id compact
	r := &reader{data: []byte{0x04, 0x00}, pos: 0}
	_, err := readFields(r)
	require.Error(t, err)
}

func TestReadFieldsTruncatedTypeName(t *testing.T) {
	// 1 field, name=None, type_id=0, truncated at typeName readOptionString
	r := &reader{data: []byte{0x04, 0x00, 0x00}, pos: 0}
	_, err := readFields(r)
	require.Error(t, err)
}

func TestReadFieldsTruncatedDocs(t *testing.T) {
	// 1 field, name=None, type_id=0, typeName=None, truncated at docs
	r := &reader{data: []byte{0x04, 0x00, 0x00, 0x00}, pos: 0}
	_, err := readFields(r)
	require.Error(t, err)
}

func TestReadFieldsTruncatedCount(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := readFields(r)
	require.Error(t, err)
}

func TestSkipTypeParamsTruncatedCount(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	err := skipTypeParams(r)
	require.Error(t, err)
}

func TestSkipTypeParamsTruncatedName(t *testing.T) {
	// 1 param, truncated at name
	r := &reader{data: []byte{0x04}, pos: 0}
	err := skipTypeParams(r)
	require.Error(t, err)
}

func TestSkipTypeParamsTruncatedTag(t *testing.T) {
	// 1 param, name="x", truncated at tag
	r := &reader{data: []byte{0x04, 0x04, 'x'}, pos: 0}
	err := skipTypeParams(r)
	require.Error(t, err)
}

func TestSkipTypeParamsSomeTruncatedCompact(t *testing.T) {
	// 1 param, name="x", tag=1 (Some), truncated at compact
	r := &reader{data: []byte{0x04, 0x04, 'x', 0x01}, pos: 0}
	err := skipTypeParams(r)
	require.Error(t, err)
}

func TestReadRegistryTruncatedCount(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := readRegistry(r)
	require.Error(t, err)
}

func TestReadRegistryTruncatedTypeId(t *testing.T) {
	// 1 type, truncated at type_id compact
	r := &reader{data: []byte{0x04}, pos: 0}
	_, err := readRegistry(r)
	require.Error(t, err)
}

func TestReadRegistryTruncatedPath(t *testing.T) {
	// 1 type, type_id=0, truncated at path strings
	r := &reader{data: []byte{0x04, 0x00}, pos: 0}
	_, err := readRegistry(r)
	require.Error(t, err)
}

func TestReadRegistryTruncatedTypeParams(t *testing.T) {
	// 1 type, type_id=0, path=0 strings, truncated at type_params
	r := &reader{data: []byte{0x04, 0x00, 0x00}, pos: 0}
	_, err := readRegistry(r)
	require.Error(t, err)
}

func TestReadRegistryTruncatedTypeDef(t *testing.T) {
	// 1 type, type_id=0, path=0, params=0, truncated at typedef
	r := &reader{data: []byte{0x04, 0x00, 0x00, 0x00}, pos: 0}
	_, err := readRegistry(r)
	require.Error(t, err)
}

func TestReadRegistryTruncatedDocs(t *testing.T) {
	// 1 type, type_id=0, path=0, params=0, typedef=composite(0 fields), truncated at docs
	r := &reader{data: []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00}, pos: 0}
	_, err := readRegistry(r)
	require.Error(t, err)
}

func TestWalkPalletsTruncatedCount(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsTruncatedName(t *testing.T) {
	// 1 pallet, truncated at name
	r := &reader{data: []byte{0x04}, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsTruncatedStorageTag(t *testing.T) {
	// 1 pallet, name="S" (compact 1 + 'S'), truncated at storage option tag
	r := &reader{data: []byte{0x04, 0x04, 'S'}, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsStorageTruncatedPrefix(t *testing.T) {
	// 1 pallet, name="S", storage=Some(1), truncated at prefix string
	r := &reader{data: []byte{0x04, 0x04, 'S', 0x01}, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsStorageTruncatedEntryCount(t *testing.T) {
	// name="S", storage=Some, prefix="P", truncated at entry count
	data := []byte{0x04, 0x04, 'S', 0x01, 0x04, 'P'}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsStorageTruncatedEntryName(t *testing.T) {
	// name="S", storage=Some, prefix="P", 1 entry, truncated at entry name
	data := []byte{0x04, 0x04, 'S', 0x01, 0x04, 'P', 0x04}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsStorageTruncatedModifier(t *testing.T) {
	// ... 1 entry, name="E", truncated at modifier (readU8)
	data := []byte{0x04, 0x04, 'S', 0x01, 0x04, 'P', 0x04, 0x04, 'E'}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsStorageTruncatedValueType(t *testing.T) {
	// entry name="E", modifier=0, truncated at readStorageEntryValueType
	data := []byte{0x04, 0x04, 'S', 0x01, 0x04, 'P', 0x04, 0x04, 'E', 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsStorageTruncatedDefault(t *testing.T) {
	// entry done through valueType, truncated at readVecU8 (default value)
	data := []byte{0x04, 0x04, 'S', 0x01, 0x04, 'P', 0x04, 0x04, 'E', 0x00, 0x00, 0x0C}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsStorageTruncatedDocs(t *testing.T) {
	// entry done through default, truncated at skipStrings (docs)
	data := []byte{0x04, 0x04, 'S', 0x01, 0x04, 'P', 0x04, 0x04, 'E', 0x00, 0x00, 0x0C, 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsNoStorageTruncatedCallsTag(t *testing.T) {
	// name="S", storage=None(0), truncated at calls option tag
	data := []byte{0x04, 0x04, 'S', 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsCallsSomeTruncatedType(t *testing.T) {
	// name="S", storage=None, calls=Some(1), truncated at compact type
	data := []byte{0x04, 0x04, 'S', 0x00, 0x01}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsTruncatedEventsTag(t *testing.T) {
	// name="S", storage=None, calls=None, truncated at events option (skipOptionalCompact)
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsTruncatedConstCount(t *testing.T) {
	// name="S", storage=None, calls=None, events=None, truncated at const count
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsConstTruncatedName(t *testing.T) {
	// ... events=None, 1 constant, truncated at name
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00, 0x04}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsConstTruncatedType(t *testing.T) {
	// 1 constant, name="C", truncated at type compact
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00, 0x04, 0x04, 'C'}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsConstTruncatedValue(t *testing.T) {
	// name="C", type=0, truncated at readVecU8 (value)
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00, 0x04, 0x04, 'C', 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsConstTruncatedConstDocs(t *testing.T) {
	// name="C", type=0, value=empty, truncated at skipStrings
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00, 0x04, 0x04, 'C', 0x00, 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsTruncatedErrorTag(t *testing.T) {
	// 0 constants, truncated at error option tag
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00, 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsErrorSomeTruncatedType(t *testing.T) {
	// 0 constants, error=Some(1), truncated at compact type
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00, 0x00, 0x01}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsTruncatedPalletIndex(t *testing.T) {
	// 0 consts, error=None, truncated at palletIndex readU8
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00, 0x00, 0x00}
	r := &reader{data: data, pos: 0}
	_, err := walkPallets(r)
	require.Error(t, err)
}

func TestWalkPalletsCompletePalletNoStorage(t *testing.T) {
	// Minimal complete pallet: name="S", storage=None, calls=None, events=None,
	// 0 constants, error=None, palletIndex=0
	data := []byte{0x04, 0x04, 'S', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	r := &reader{data: data, pos: 0}
	result, err := walkPallets(r)
	require.NoError(t, err)
	require.Empty(t, result.storage)
	require.Empty(t, result.pendingCalls)
	require.Empty(t, result.pendingErrors)
}

func TestReadStorageEntryValueTypeTruncatedTag(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := readStorageEntryValueType(r)
	require.Error(t, err)
}

func TestReadStorageEntryValueTypePlainTruncated(t *testing.T) {
	// tag=0, truncated compact
	r := &reader{data: []byte{0x00}, pos: 0}
	_, err := readStorageEntryValueType(r)
	require.Error(t, err)
}

func TestReadStorageEntryValueTypeMapTruncatedHasherCount(t *testing.T) {
	// tag=1, truncated at hasher count compact
	r := &reader{data: []byte{0x01}, pos: 0}
	_, err := readStorageEntryValueType(r)
	require.Error(t, err)
}

func TestReadStorageEntryValueTypeMapTruncatedHasher(t *testing.T) {
	// tag=1, 1 hasher, truncated at hasher byte
	r := &reader{data: []byte{0x01, 0x04}, pos: 0}
	_, err := readStorageEntryValueType(r)
	require.Error(t, err)
}

func TestReadStorageEntryValueTypeMapTruncatedKeyType(t *testing.T) {
	// tag=1, 1 hasher, hasher=0, truncated at key_type compact
	r := &reader{data: []byte{0x01, 0x04, 0x00}, pos: 0}
	_, err := readStorageEntryValueType(r)
	require.Error(t, err)
}

func TestReadStorageEntryValueTypeMapTruncatedValueType(t *testing.T) {
	// tag=1, 1 hasher, hasher=0, key_type=0, truncated at value_type compact
	r := &reader{data: []byte{0x01, 0x04, 0x00, 0x00}, pos: 0}
	_, err := readStorageEntryValueType(r)
	require.Error(t, err)
}

func TestSkipOptionalCompactTruncatedTag(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	err := skipOptionalCompact(r)
	require.Error(t, err)
}

func TestSkipOptionalCompactSomeTruncated(t *testing.T) {
	// tag=1 (Some), truncated compact
	r := &reader{data: []byte{0x01}, pos: 0}
	err := skipOptionalCompact(r)
	require.Error(t, err)
}

func TestOptionTagTruncated(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := optionTag(r)
	require.Error(t, err)
}

func TestReadOptionStringTruncatedString(t *testing.T) {
	// tag=1 (Some), string compact=10 but no data
	r := &reader{data: []byte{0x01, 0x28}, pos: 0}
	_, _, err := r.readOptionString()
	require.Error(t, err)
}

func TestReadStringCompactTruncated(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := r.readString()
	require.Error(t, err)
}

func TestReadVecU8CompactTruncated(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := r.readVecU8()
	require.Error(t, err)
}

func TestReadVecStringCompactTruncated(t *testing.T) {
	r := &reader{data: []byte{}, pos: 0}
	_, err := r.readVecString()
	require.Error(t, err)
}

func TestWalkPalletsStorageEntryCompleteWithDocs(t *testing.T) {
	// name="S", storage=Some, prefix="P", 1 entry named "E",
	// modifier=0, plain type_id=5, default=empty, docs=0
	// then calls=None, events=None, 0 consts, error=None, palletIdx=0
	data := []byte{
		0x04,       // 1 pallet
		0x04, 'S',  // name
		0x01,       // storage=Some
		0x04, 'P',  // prefix
		0x04,       // 1 entry
		0x04, 'E',  // entry name
		0x00,       // modifier
		0x00, 0x14, // plain, type_id=5
		0x00,       // default vec (empty)
		0x00,       // docs (empty)
		0x00,       // calls=None
		0x00,       // events=None
		0x00,       // 0 constants
		0x00,       // error=None
		0x00,       // palletIndex=0
	}
	r := &reader{data: data, pos: 0}
	result, err := walkPallets(r)
	require.NoError(t, err)
	ty, ok := result.storage[storageKey{"S", "E"}]
	require.True(t, ok)
	require.Equal(t, uint32(5), ty)
}

func TestWalkPalletsWithCallsAndErrors(t *testing.T) {
	// name="S", storage=None, calls=Some(type=3), events=None,
	// 0 consts, error=Some(type=7), palletIdx=1
	data := []byte{
		0x04,       // 1 pallet
		0x04, 'S',  // name
		0x00,       // storage=None
		0x01, 0x0C, // calls=Some, type=3
		0x00,       // events=None
		0x00,       // 0 constants
		0x01, 0x1C, // error=Some, type=7
		0x01,       // palletIndex=1
	}
	r := &reader{data: data, pos: 0}
	result, err := walkPallets(r)
	require.NoError(t, err)
	require.Len(t, result.pendingCalls, 1)
	require.Equal(t, uint32(3), result.pendingCalls[0].CallsTy)
	require.Len(t, result.pendingErrors, 1)
	require.Equal(t, uint32(7), result.pendingErrors[0].ErrorTy)
}

func TestStorageLayoutByteSizeErrorPropagates(t *testing.T) {
	// A metadata where the storage entry refers to a composite with a variable-width field
	// preceding the target field. This exercises byteSize error propagation in StorageLayout.
	m := &Metadata{
		registry: []typeShape{
			variableShape{},                          // type 0: variable
			primitiveShape{Width: 4, UnsignedInt: true}, // type 1: u32
			compositeShape{Fields: []compositeField{
				{Name: "bad", Type: 0},
				{Name: "good", Type: 1},
			}}, // type 2
		},
		storage: map[storageKey]uint32{
			{"P", "E"}: 2,
		},
		calls:  map[callKey][2]uint8{},
		Errors: NewErrorTable(),
	}
	_, err := m.StorageLayout("P", "E", []string{"good"})
	require.Error(t, err)
}

func TestStorageLayoutTypeAtError(t *testing.T) {
	m := &Metadata{
		registry: []typeShape{},
		storage: map[storageKey]uint32{
			{"P", "E"}: 999,
		},
		calls:  map[callKey][2]uint8{},
		Errors: NewErrorTable(),
	}
	_, err := m.StorageLayout("P", "E", []string{})
	require.Error(t, err)
}

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
	require.Equal(t, uint8(0), palletIdx.Get())
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
