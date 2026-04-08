package samp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const metadataMagic uint32 = 0x6174_656d

type MetadataError struct {
	Kind string
	Msg  string
}

func (e *MetadataError) Error() string {
	return "samp: metadata: " + e.Msg
}

func newMetadataError(kind, msg string) *MetadataError {
	return &MetadataError{Kind: kind, Msg: msg}
}

type StorageLayout struct {
	Offset int
	Width  int
}

func (l StorageLayout) DecodeUint(data []byte) (uint64, error) {
	end := l.Offset + l.Width
	if len(data) < end {
		return 0, newMetadataError("storage_value_too_short",
			fmt.Sprintf("storage value too short: need %d bytes, got %d", end, len(data)))
	}
	var buf [8]byte
	width := l.Width
	if width > 8 {
		width = 8
	}
	copy(buf[:width], data[l.Offset:l.Offset+width])
	return binary.LittleEndian.Uint64(buf[:]), nil
}

type ErrorEntry struct {
	Pallet  string
	Variant string
	Doc     string
}

type errorKey struct {
	PalletIdx uint8
	ErrIdx    uint8
}

type ErrorTable struct {
	byIdx map[errorKey]ErrorEntry
}

func NewErrorTable() *ErrorTable {
	return &ErrorTable{byIdx: make(map[errorKey]ErrorEntry)}
}

func (t *ErrorTable) Humanize(palletIdx, errIdx uint8) (string, bool) {
	entry, ok := t.byIdx[errorKey{palletIdx, errIdx}]
	if !ok {
		return "", false
	}
	if entry.Doc == "" {
		return entry.Pallet + "::" + entry.Variant, true
	}
	return entry.Pallet + "::" + entry.Variant + ": " + entry.Doc, true
}

func (t *ErrorTable) HumanizeRpcError(raw string) string {
	payload, ok := findAfterAny(raw, []string{"RPC error: ", "transaction failed: "})
	if ok {
		jsonStr, ok := trimToJson(payload)
		if ok {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
				if data, ok := parsed["data"].(string); ok {
					if translated, ok := t.maybeTranslateModule(data); ok {
						return translated
					}
					return data
				}
				if message, ok := parsed["message"].(string); ok {
					return message
				}
			}
		}
	}
	if translated, ok := t.maybeTranslateModule(raw); ok {
		return translated
	}
	return raw
}

func (t *ErrorTable) maybeTranslateModule(s string) (string, bool) {
	start := strings.Index(s, "Module")
	if start < 0 {
		return "", false
	}
	tail := s[start:]
	idx, ok := parseAfter(tail, "index:")
	if !ok {
		return "", false
	}
	errIdx, ok := parseFirstByteAfter(tail, "error:")
	if !ok {
		return "", false
	}
	if idx > 255 || errIdx > 255 {
		return "", false
	}
	return t.Humanize(uint8(idx), uint8(errIdx))
}

func findAfterAny(s string, needles []string) (string, bool) {
	for _, n := range needles {
		i := strings.Index(s, n)
		if i >= 0 {
			return s[i+len(n):], true
		}
	}
	return "", false
}

func trimToJson(s string) (string, bool) {
	start := strings.Index(s, "{")
	if start < 0 {
		return "", false
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		b := s[i]
		if esc {
			esc = false
			continue
		}
		if inStr && b == '\\' {
			esc = true
			continue
		}
		if b == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		if b == '{' {
			depth++
		} else if b == '}' {
			depth--
			if depth == 0 {
				return s[start : i+1], true
			}
		}
	}
	return "", false
}

var (
	digitsAfter   = regexp.MustCompile(`^\s*(\d+)`)
	digitsBracket = regexp.MustCompile(`\[(\d+)`)
)

func parseAfter(haystack, needle string) (int, bool) {
	i := strings.Index(haystack, needle)
	if i < 0 {
		return 0, false
	}
	rest := haystack[i+len(needle):]
	m := digitsAfter.FindStringSubmatch(rest)
	if m == nil {
		return 0, false
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseFirstByteAfter(haystack, needle string) (int, bool) {
	i := strings.Index(haystack, needle)
	if i < 0 {
		return 0, false
	}
	rest := haystack[i+len(needle):]
	m := digitsBracket.FindStringSubmatch(rest)
	if m == nil {
		return 0, false
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return v, true
}

type typeShape interface {
	isTypeShape()
}

type primitiveShape struct {
	Width       int
	UnsignedInt bool
}

type compositeShape struct {
	Fields []compositeField
}

type compositeField struct {
	Name string
	Type uint32
}

type arrayShape struct {
	Length uint32
	Inner  uint32
}

type tupleShape struct {
	Ids []uint32
}

type variantShape struct {
	Entries []variantEntry
}

type variantEntry struct {
	Index uint8
	Name  string
	Doc   string
}

type variableShape struct{}

func (primitiveShape) isTypeShape() {}
func (compositeShape) isTypeShape() {}
func (arrayShape) isTypeShape()     {}
func (tupleShape) isTypeShape()     {}
func (variantShape) isTypeShape()   {}
func (variableShape) isTypeShape()  {}

var variableSingleton = variableShape{}

type storageKey struct {
	Pallet string
	Entry  string
}

type callKey struct {
	Pallet string
	Call   string
}

type Metadata struct {
	registry []typeShape
	storage  map[storageKey]uint32
	calls    map[callKey][2]uint8
	Errors   *ErrorTable
}

func MetadataFromRuntimeMetadata(data []byte) (*Metadata, error) {
	r := &reader{data: data}
	magic, err := r.readU32()
	if err != nil {
		return nil, newMetadataError("scale", err.Error())
	}
	if magic != metadataMagic {
		return nil, newMetadataError("scale", fmt.Sprintf("metadata magic mismatch: 0x%08x", magic))
	}
	version, err := r.readU8()
	if err != nil {
		return nil, newMetadataError("scale", err.Error())
	}
	if version != 14 {
		return nil, newMetadataError("scale", fmt.Sprintf("metadata version %d unsupported (need V14)", version))
	}

	registry, err := readRegistry(r)
	if err != nil {
		return nil, err
	}
	walked, err := walkPallets(r)
	if err != nil {
		return nil, err
	}
	errors := buildErrorTable(registry, walked.pendingErrors)
	calls := resolveCallIndices(registry, walked.pendingCalls)

	return &Metadata{
		registry: registry,
		storage:  walked.storage,
		calls:    calls,
		Errors:   errors,
	}, nil
}

func (m *Metadata) StorageLayout(pallet, entry string, fieldPath []string) (StorageLayout, error) {
	valueTy, ok := m.storage[storageKey{pallet, entry}]
	if !ok {
		return StorageLayout{}, newMetadataError("storage_not_found",
			fmt.Sprintf("storage entry not found: %s.%s", pallet, entry))
	}
	offset := 0
	current := valueTy
	for _, fieldName := range fieldPath {
		shape, err := m.typeAt(current)
		if err != nil {
			return StorageLayout{}, err
		}
		comp, ok := shape.(compositeShape)
		if !ok {
			return StorageLayout{}, newMetadataError("shape", "path traversal is not a composite at "+fieldName)
		}
		var found *uint32
		for _, f := range comp.Fields {
			if f.Name == fieldName {
				ty := f.Type
				found = &ty
				break
			}
			size, err := m.byteSize(f.Type)
			if err != nil {
				return StorageLayout{}, err
			}
			offset += size
		}
		if found == nil {
			return StorageLayout{}, newMetadataError("field_not_found", "field not found: "+fieldName)
		}
		current = *found
	}
	shape, err := m.typeAt(current)
	if err != nil {
		return StorageLayout{}, err
	}
	prim, ok := shape.(primitiveShape)
	if !ok || !prim.UnsignedInt {
		return StorageLayout{}, newMetadataError("shape", "storage_layout target is not an unsigned integer primitive")
	}
	return StorageLayout{Offset: offset, Width: prim.Width}, nil
}

func (m *Metadata) FindCallIndex(pallet, call string) (uint8, uint8, bool) {
	v, ok := m.calls[callKey{pallet, call}]
	if !ok {
		return 0, 0, false
	}
	return v[0], v[1], true
}

func (m *Metadata) typeAt(typeId uint32) (typeShape, error) {
	if int(typeId) >= len(m.registry) {
		return nil, newMetadataError("type_id_missing", fmt.Sprintf("type id %d missing from registry", typeId))
	}
	return m.registry[typeId], nil
}

func (m *Metadata) byteSize(typeId uint32) (int, error) {
	shape, err := m.typeAt(typeId)
	if err != nil {
		return 0, err
	}
	switch s := shape.(type) {
	case primitiveShape:
		return s.Width, nil
	case compositeShape:
		sum := 0
		for _, f := range s.Fields {
			n, err := m.byteSize(f.Type)
			if err != nil {
				return 0, err
			}
			sum += n
		}
		return sum, nil
	case arrayShape:
		n, err := m.byteSize(s.Inner)
		if err != nil {
			return 0, err
		}
		return int(s.Length) * n, nil
	case tupleShape:
		sum := 0
		for _, t := range s.Ids {
			n, err := m.byteSize(t)
			if err != nil {
				return 0, err
			}
			sum += n
		}
		return sum, nil
	}
	return 0, newMetadataError("variable_width", fmt.Sprintf("type id %d has variable width", typeId))
}

type reader struct {
	data []byte
	pos  int
}

func (r *reader) read(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("insufficient data: need %d bytes at %d, have %d", n, r.pos, len(r.data)-r.pos)
	}
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *reader) readU8() (uint8, error) {
	b, err := r.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) readU32() (uint32, error) {
	b, err := r.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *reader) readCompact() (uint32, error) {
	value, consumed, err := DecodeCompact(r.data[r.pos:])
	if err != nil {
		return 0, err
	}
	r.pos += consumed
	if value > 1<<32-1 {
		return 0, fmt.Errorf("compact value %d exceeds u32", value)
	}
	return uint32(value), nil
}

func (r *reader) readString() (string, error) {
	length, err := r.readCompact()
	if err != nil {
		return "", err
	}
	b, err := r.read(int(length))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *reader) readOptionString() (string, bool, error) {
	tag, err := r.readU8()
	if err != nil {
		return "", false, err
	}
	if tag == 0 {
		return "", false, nil
	}
	if tag == 1 {
		s, err := r.readString()
		if err != nil {
			return "", false, err
		}
		return s, true, nil
	}
	return "", false, fmt.Errorf("invalid Option tag %d", tag)
}

func (r *reader) readVecString() ([]string, error) {
	n, err := r.readCompact()
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i := uint32(0); i < n; i++ {
		s, err := r.readString()
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

func (r *reader) readVecU8() ([]byte, error) {
	n, err := r.readCompact()
	if err != nil {
		return nil, err
	}
	return r.read(int(n))
}

func (r *reader) skipStrings() error {
	_, err := r.readVecString()
	return err
}

func readRegistry(r *reader) ([]typeShape, error) {
	n, err := r.readCompact()
	if err != nil {
		return nil, newMetadataError("scale", err.Error())
	}
	out := make([]typeShape, 0, n)
	for expected := uint32(0); expected < n; expected++ {
		typeId, err := r.readCompact()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		if typeId != expected {
			return nil, newMetadataError("scale",
				fmt.Sprintf("non-sequential type id %d (expected %d)", typeId, expected))
		}
		if err := r.skipStrings(); err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		if err := skipTypeParams(r); err != nil {
			return nil, err
		}
		shape, err := readTypeDef(r)
		if err != nil {
			return nil, err
		}
		out = append(out, shape)
		if err := r.skipStrings(); err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
	}
	return out, nil
}

func readTypeDef(r *reader) (typeShape, error) {
	tag, err := r.readU8()
	if err != nil {
		return nil, newMetadataError("scale", err.Error())
	}
	switch tag {
	case 0:
		fields, err := readFields(r)
		if err != nil {
			return nil, err
		}
		return compositeShape{Fields: fields}, nil
	case 1:
		n, err := r.readCompact()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		entries := make([]variantEntry, 0, n)
		for i := uint32(0); i < n; i++ {
			name, err := r.readString()
			if err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			if _, err := readFields(r); err != nil {
				return nil, err
			}
			index, err := r.readU8()
			if err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			docs, err := r.readVecString()
			if err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			doc := ""
			for _, d := range docs {
				if t := strings.TrimSpace(d); t != "" {
					doc = t
					break
				}
			}
			entries = append(entries, variantEntry{Index: index, Name: name, Doc: doc})
		}
		return variantShape{Entries: entries}, nil
	case 2:
		if _, err := r.readCompact(); err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		return variableSingleton, nil
	case 3:
		length, err := r.readU32()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		inner, err := r.readCompact()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		return arrayShape{Length: length, Inner: inner}, nil
	case 4:
		n, err := r.readCompact()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		ids := make([]uint32, 0, n)
		for i := uint32(0); i < n; i++ {
			id, err := r.readCompact()
			if err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			ids = append(ids, id)
		}
		return tupleShape{Ids: ids}, nil
	case 5:
		t, err := r.readU8()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		return primitiveFromTag(t)
	case 6:
		if _, err := r.readCompact(); err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		return variableSingleton, nil
	case 7:
		if _, err := r.readCompact(); err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		if _, err := r.readCompact(); err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		return variableSingleton, nil
	}
	return nil, newMetadataError("scale", fmt.Sprintf("unknown TypeDef tag %d", tag))
}

func readFields(r *reader) ([]compositeField, error) {
	n, err := r.readCompact()
	if err != nil {
		return nil, newMetadataError("scale", err.Error())
	}
	out := make([]compositeField, 0, n)
	for i := uint32(0); i < n; i++ {
		name, _, err := r.readOptionString()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		ty, err := r.readCompact()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		if _, _, err := r.readOptionString(); err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		if err := r.skipStrings(); err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		out = append(out, compositeField{Name: name, Type: ty})
	}
	return out, nil
}

func skipTypeParams(r *reader) error {
	n, err := r.readCompact()
	if err != nil {
		return newMetadataError("scale", err.Error())
	}
	for i := uint32(0); i < n; i++ {
		if _, err := r.readString(); err != nil {
			return newMetadataError("scale", err.Error())
		}
		tag, err := r.readU8()
		if err != nil {
			return newMetadataError("scale", err.Error())
		}
		if tag == 0 {
			continue
		}
		if tag == 1 {
			if _, err := r.readCompact(); err != nil {
				return newMetadataError("scale", err.Error())
			}
			continue
		}
		return newMetadataError("scale", fmt.Sprintf("invalid Option tag %d", tag))
	}
	return nil
}

func primitiveFromTag(tag uint8) (typeShape, error) {
	table := map[uint8]struct {
		width    int
		unsigned bool
	}{
		0:  {1, false},
		1:  {4, false},
		3:  {1, true},
		4:  {2, true},
		5:  {4, true},
		6:  {8, true},
		7:  {16, true},
		8:  {32, true},
		9:  {1, false},
		10: {2, false},
		11: {4, false},
		12: {8, false},
		13: {16, false},
		14: {32, false},
	}
	if tag == 2 {
		return variableSingleton, nil
	}
	v, ok := table[tag]
	if !ok {
		return nil, newMetadataError("scale", fmt.Sprintf("unknown primitive tag %d", tag))
	}
	return primitiveShape{Width: v.width, UnsignedInt: v.unsigned}, nil
}

type palletWalkResult struct {
	storage       map[storageKey]uint32
	pendingCalls  []pendingCall
	pendingErrors []pendingError
}

type pendingCall struct {
	Pallet    string
	PalletIdx uint8
	CallsTy   uint32
}

type pendingError struct {
	Pallet    string
	PalletIdx uint8
	ErrorTy   uint32
}

func walkPallets(r *reader) (*palletWalkResult, error) {
	result := &palletWalkResult{
		storage: make(map[storageKey]uint32),
	}
	n, err := r.readCompact()
	if err != nil {
		return nil, newMetadataError("scale", err.Error())
	}
	for i := uint32(0); i < n; i++ {
		palletName, err := r.readString()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		hasStorage, err := optionTag(r)
		if err != nil {
			return nil, err
		}
		if hasStorage {
			if _, err := r.readString(); err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			entryCount, err := r.readCompact()
			if err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			for j := uint32(0); j < entryCount; j++ {
				entryName, err := r.readString()
				if err != nil {
					return nil, newMetadataError("scale", err.Error())
				}
				if _, err := r.readU8(); err != nil {
					return nil, newMetadataError("scale", err.Error())
				}
				valueTy, err := readStorageEntryValueType(r)
				if err != nil {
					return nil, err
				}
				result.storage[storageKey{palletName, entryName}] = valueTy
				if _, err := r.readVecU8(); err != nil {
					return nil, newMetadataError("scale", err.Error())
				}
				if err := r.skipStrings(); err != nil {
					return nil, newMetadataError("scale", err.Error())
				}
			}
		}
		hasCalls, err := optionTag(r)
		if err != nil {
			return nil, err
		}
		var callsTy uint32
		callsTySet := false
		if hasCalls {
			callsTy, err = r.readCompact()
			if err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			callsTySet = true
		}
		if err := skipOptionalCompact(r); err != nil {
			return nil, err
		}
		constCount, err := r.readCompact()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		for j := uint32(0); j < constCount; j++ {
			if _, err := r.readString(); err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			if _, err := r.readCompact(); err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			if _, err := r.readVecU8(); err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			if err := r.skipStrings(); err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
		}
		hasError, err := optionTag(r)
		if err != nil {
			return nil, err
		}
		var errorTy uint32
		errorTySet := false
		if hasError {
			errorTy, err = r.readCompact()
			if err != nil {
				return nil, newMetadataError("scale", err.Error())
			}
			errorTySet = true
		}
		palletIndex, err := r.readU8()
		if err != nil {
			return nil, newMetadataError("scale", err.Error())
		}
		if callsTySet {
			result.pendingCalls = append(result.pendingCalls,
				pendingCall{Pallet: palletName, PalletIdx: palletIndex, CallsTy: callsTy})
		}
		if errorTySet {
			result.pendingErrors = append(result.pendingErrors,
				pendingError{Pallet: palletName, PalletIdx: palletIndex, ErrorTy: errorTy})
		}
	}
	return result, nil
}

func readStorageEntryValueType(r *reader) (uint32, error) {
	tag, err := r.readU8()
	if err != nil {
		return 0, newMetadataError("scale", err.Error())
	}
	if tag == 0 {
		v, err := r.readCompact()
		if err != nil {
			return 0, newMetadataError("scale", err.Error())
		}
		return v, nil
	}
	if tag == 1 {
		n, err := r.readCompact()
		if err != nil {
			return 0, newMetadataError("scale", err.Error())
		}
		for i := uint32(0); i < n; i++ {
			if _, err := r.readU8(); err != nil {
				return 0, newMetadataError("scale", err.Error())
			}
		}
		if _, err := r.readCompact(); err != nil {
			return 0, newMetadataError("scale", err.Error())
		}
		v, err := r.readCompact()
		if err != nil {
			return 0, newMetadataError("scale", err.Error())
		}
		return v, nil
	}
	return 0, newMetadataError("scale", fmt.Sprintf("unknown StorageEntryType tag %d", tag))
}

func optionTag(r *reader) (bool, error) {
	tag, err := r.readU8()
	if err != nil {
		return false, newMetadataError("scale", err.Error())
	}
	if tag == 0 {
		return false, nil
	}
	if tag == 1 {
		return true, nil
	}
	return false, newMetadataError("scale", fmt.Sprintf("invalid Option tag %d", tag))
}

func skipOptionalCompact(r *reader) error {
	ok, err := optionTag(r)
	if err != nil {
		return err
	}
	if ok {
		if _, err := r.readCompact(); err != nil {
			return newMetadataError("scale", err.Error())
		}
	}
	return nil
}

func buildErrorTable(registry []typeShape, pending []pendingError) *ErrorTable {
	table := NewErrorTable()
	for _, p := range pending {
		if int(p.ErrorTy) >= len(registry) {
			continue
		}
		shape, ok := registry[p.ErrorTy].(variantShape)
		if !ok {
			continue
		}
		for _, e := range shape.Entries {
			table.byIdx[errorKey{p.PalletIdx, e.Index}] = ErrorEntry{
				Pallet:  p.Pallet,
				Variant: e.Name,
				Doc:     e.Doc,
			}
		}
	}
	return table
}

func resolveCallIndices(registry []typeShape, pending []pendingCall) map[callKey][2]uint8 {
	out := make(map[callKey][2]uint8)
	for _, p := range pending {
		if int(p.CallsTy) >= len(registry) {
			continue
		}
		shape, ok := registry[p.CallsTy].(variantShape)
		if !ok {
			continue
		}
		for _, e := range shape.Entries {
			out[callKey{p.Pallet, e.Name}] = [2]uint8{p.PalletIdx, e.Index}
		}
	}
	return out
}
