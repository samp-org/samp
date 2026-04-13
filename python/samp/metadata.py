from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional, Union

from samp.scale import decode_compact

METADATA_MAGIC = 0x6174_656D


class MetadataError(Exception):
    pass


class ScaleError(MetadataError):
    pass


class StorageNotFoundError(MetadataError):
    pass


class FieldNotFoundError(MetadataError):
    pass


class StorageValueTooShortError(MetadataError):
    pass


class TypeIdMissingError(MetadataError):
    pass


class VariableWidthError(MetadataError):
    pass


class ShapeError(MetadataError):
    pass


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ScaleError(
                f"insufficient data: need {n} bytes at {self.pos}, have {len(self.data) - self.pos}"
            )
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def read_compact(self) -> int:
        decoded = decode_compact(self.data[self.pos :])
        if decoded is None:
            raise ScaleError("insufficient data for compact integer")
        value, consumed = decoded
        self.pos += consumed
        return value

    def read_string(self) -> str:
        length = self.read_compact()
        return self.read(length).decode("utf-8")

    def read_option_string(self) -> Optional[str]:
        tag = self.read_u8()
        if tag == 0:
            return None
        if tag == 1:
            return self.read_string()
        raise ScaleError(f"invalid Option tag {tag}")

    def read_vec_string(self) -> list[str]:
        n = self.read_compact()
        return [self.read_string() for _ in range(n)]

    def read_vec_u8(self) -> bytes:
        n = self.read_compact()
        return self.read(n)

    def skip_strings(self) -> None:
        self.read_vec_string()


@dataclass(frozen=True)
class _Primitive:
    width: int
    unsigned_int: bool


@dataclass(frozen=True)
class _Composite:
    fields: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class _Array:
    length: int
    inner: int


@dataclass(frozen=True)
class _Tuple:
    ids: tuple[int, ...]


@dataclass(frozen=True)
class _Variant:
    entries: tuple[tuple[int, str, str], ...]


@dataclass(frozen=True)
class _Variable:
    pass


_VARIABLE = _Variable()

_TypeShape = Union[_Primitive, _Composite, _Array, _Tuple, _Variant, _Variable]


@dataclass(frozen=True)
class StorageLayout:
    offset: int
    width: int

    def decode_uint(self, data: bytes) -> int:
        end = self.offset + self.width
        if len(data) < end:
            raise StorageValueTooShortError(
                f"storage value too short: need {end} bytes, got {len(data)}"
            )
        return int.from_bytes(data[self.offset : end], "little")


@dataclass(frozen=True)
class ErrorEntry:
    pallet: str
    variant: str
    doc: str


@dataclass
class ErrorTable:
    by_idx: dict[tuple[int, int], ErrorEntry] = field(default_factory=dict)

    def humanize(self, pallet_idx: int, err_idx: int) -> Optional[str]:
        entry = self.by_idx.get((pallet_idx, err_idx))
        if entry is None:
            return None
        if not entry.doc:
            return f"{entry.pallet}::{entry.variant}"
        return f"{entry.pallet}::{entry.variant}: {entry.doc}"

    def humanize_rpc_error(self, raw: str) -> str:
        payload = _find_after_any(raw, ["RPC error: ", "transaction failed: "])
        if payload is not None:
            json_str = _trim_to_json(payload)
            if json_str is not None:
                try:
                    parsed = json.loads(json_str)
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, dict):
                    data = parsed.get("data")
                    if isinstance(data, str):
                        translated = self._maybe_translate_module(data)
                        return translated if translated is not None else data
                    message = parsed.get("message")
                    if isinstance(message, str):
                        return message
        translated = self._maybe_translate_module(raw)
        if translated is not None:
            return translated
        return raw

    def _maybe_translate_module(self, s: str) -> Optional[str]:
        start = s.find("Module")
        if start < 0:
            return None
        tail = s[start:]
        idx = _parse_after(tail, "index:")
        err = _parse_first_byte_after(tail, "error:")
        if idx is None or err is None:
            return None
        if idx > 255 or err > 255:
            return None
        return self.humanize(idx, err)


def _find_after_any(s: str, needles: list[str]) -> Optional[str]:
    for n in needles:
        i = s.find(n)
        if i >= 0:
            return s[i + len(n) :]
    return None


def _trim_to_json(s: str) -> Optional[str]:
    start = s.find("{")
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(s)):
        b = s[i]
        if esc:
            esc = False
            continue
        if in_str and b == "\\":
            esc = True
            continue
        if b == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if b == "{":
            depth += 1
        elif b == "}":
            depth -= 1
            if depth == 0:
                return s[start : i + 1]
    return None


_DIGITS_AFTER = re.compile(r"\s*(\d+)")
_DIGITS_BRACKET = re.compile(r"\[(\d+)")


def _parse_after(haystack: str, needle: str) -> Optional[int]:
    i = haystack.find(needle)
    if i < 0:
        return None
    rest = haystack[i + len(needle) :]
    m = _DIGITS_AFTER.match(rest)
    if m is None:
        return None
    return int(m.group(1))


def _parse_first_byte_after(haystack: str, needle: str) -> Optional[int]:
    i = haystack.find(needle)
    if i < 0:
        return None
    rest = haystack[i + len(needle) :]
    m = _DIGITS_BRACKET.search(rest)
    if m is None:
        return None
    return int(m.group(1))


@dataclass(frozen=True)
class Metadata:
    registry: tuple[_TypeShape, ...]
    storage: dict[tuple[str, str], int]
    calls: dict[tuple[str, str], tuple[int, int]]
    errors: ErrorTable

    @classmethod
    def from_runtime_metadata(cls, data: bytes) -> "Metadata":
        reader = _Reader(data)
        magic = reader.read_u32()
        if magic != METADATA_MAGIC:
            raise ScaleError(f"metadata magic mismatch: 0x{magic:08x}")
        version = reader.read_u8()
        if version != 14:
            raise ScaleError(f"metadata version {version} unsupported (need V14)")

        registry = _read_registry(reader)
        storage, pending_calls, pending_errors = _walk_pallets(reader)
        errors = _build_error_table(registry, pending_errors)
        calls = _resolve_call_indices(registry, pending_calls)

        return cls(
            registry=tuple(registry),
            storage=storage,
            calls=calls,
            errors=errors,
        )

    def storage_layout(
        self,
        pallet: str,
        entry: str,
        field_path: list[str],
    ) -> StorageLayout:
        value_ty = self.storage.get((pallet, entry))
        if value_ty is None:
            raise StorageNotFoundError(f"storage entry not found: {pallet}.{entry}")
        offset = 0
        current = value_ty
        for field_name in field_path:
            shape = _type_at(self.registry, current)
            if not isinstance(shape, _Composite):
                raise ShapeError(f"path traversal is not a composite at {field_name}")
            found: Optional[int] = None
            for name, ty in shape.fields:
                if name == field_name:
                    found = ty
                    break
                offset += _byte_size(self.registry, ty)
            if found is None:
                raise FieldNotFoundError(f"field not found: {field_name}")
            current = found
        shape = _type_at(self.registry, current)
        if not isinstance(shape, _Primitive) or not shape.unsigned_int:
            raise ShapeError("storage_layout target is not an unsigned integer primitive")
        return StorageLayout(offset=offset, width=shape.width)

    def find_call_index(self, pallet: str, call: str) -> Optional[tuple[int, int]]:
        return self.calls.get((pallet, call))


def _type_at(registry: tuple[_TypeShape, ...], type_id: int) -> _TypeShape:
    if type_id < 0 or type_id >= len(registry):
        raise TypeIdMissingError(f"type id {type_id} missing from registry")
    return registry[type_id]


def _byte_size(registry: tuple[_TypeShape, ...], type_id: int) -> int:
    shape = _type_at(registry, type_id)
    if isinstance(shape, _Primitive):
        return shape.width
    if isinstance(shape, _Composite):
        return sum(_byte_size(registry, ty) for _, ty in shape.fields)
    if isinstance(shape, _Array):
        return shape.length * _byte_size(registry, shape.inner)
    if isinstance(shape, _Tuple):
        return sum(_byte_size(registry, t) for t in shape.ids)
    raise VariableWidthError(f"type id {type_id} has variable width")


def _read_registry(reader: _Reader) -> tuple[_TypeShape, ...]:
    n = reader.read_compact()
    out: list[_TypeShape] = []
    for expected in range(n):
        type_id = reader.read_compact()
        if type_id != expected:
            raise ScaleError(f"non-sequential type id {type_id} (expected {expected})")
        reader.skip_strings()
        _skip_type_params(reader)
        out.append(_read_type_def(reader))
        reader.skip_strings()
    return tuple(out)


def _read_type_def(reader: _Reader) -> _TypeShape:
    tag = reader.read_u8()
    if tag == 0:
        return _Composite(fields=tuple(_read_fields(reader)))
    if tag == 1:
        n = reader.read_compact()
        entries: list[tuple[int, str, str]] = []
        for _ in range(n):
            name = reader.read_string()
            _read_fields(reader)
            index = reader.read_u8()
            docs = reader.read_vec_string()
            doc = next((d.strip() for d in docs if d.strip()), "")
            entries.append((index, name, doc))
        return _Variant(entries=tuple(entries))
    if tag == 2:
        reader.read_compact()
        return _VARIABLE
    if tag == 3:
        length = reader.read_u32()
        inner = reader.read_compact()
        return _Array(length=length, inner=inner)
    if tag == 4:
        n = reader.read_compact()
        ids = tuple(reader.read_compact() for _ in range(n))
        return _Tuple(ids=ids)
    if tag == 5:
        return _primitive_shape(reader.read_u8())
    if tag == 6:
        reader.read_compact()
        return _VARIABLE
    if tag == 7:
        reader.read_compact()
        reader.read_compact()
        return _VARIABLE
    raise ScaleError(f"unknown TypeDef tag {tag}")


def _read_fields(reader: _Reader) -> list[tuple[str, int]]:
    n = reader.read_compact()
    out: list[tuple[str, int]] = []
    for _ in range(n):
        name = reader.read_option_string() or ""
        ty = reader.read_compact()
        reader.read_option_string()
        reader.skip_strings()
        out.append((name, ty))
    return out


def _skip_type_params(reader: _Reader) -> None:
    n = reader.read_compact()
    for _ in range(n):
        reader.read_string()
        tag = reader.read_u8()
        if tag == 0:
            continue
        if tag == 1:
            reader.read_compact()
            continue
        raise ScaleError(f"invalid Option tag {tag}")


def _primitive_shape(tag: int) -> _TypeShape:
    table: dict[int, tuple[int, bool]] = {
        0: (1, False),
        1: (4, False),
        3: (1, True),
        4: (2, True),
        5: (4, True),
        6: (8, True),
        7: (16, True),
        8: (32, True),
        9: (1, False),
        10: (2, False),
        11: (4, False),
        12: (8, False),
        13: (16, False),
        14: (32, False),
    }
    if tag == 2:
        return _VARIABLE
    if tag not in table:
        raise ScaleError(f"unknown primitive tag {tag}")
    width, unsigned_int = table[tag]
    return _Primitive(width=width, unsigned_int=unsigned_int)


def _walk_pallets(
    reader: _Reader,
) -> tuple[
    dict[tuple[str, str], int],
    list[tuple[str, int, int]],
    list[tuple[str, int, int]],
]:
    storage: dict[tuple[str, str], int] = {}
    pending_calls: list[tuple[str, int, int]] = []
    pending_errors: list[tuple[str, int, int]] = []

    n = reader.read_compact()
    for _ in range(n):
        pallet_name = reader.read_string()

        if _option_tag(reader):
            reader.read_string()
            entry_count = reader.read_compact()
            for _ in range(entry_count):
                entry_name = reader.read_string()
                reader.read_u8()
                value_ty = _read_storage_entry_value_type(reader)
                storage[(pallet_name, entry_name)] = value_ty
                reader.read_vec_u8()
                reader.skip_strings()

        calls_ty = reader.read_compact() if _option_tag(reader) else None
        _skip_optional_compact(reader)

        const_count = reader.read_compact()
        for _ in range(const_count):
            reader.read_string()
            reader.read_compact()
            reader.read_vec_u8()
            reader.skip_strings()

        error_ty = reader.read_compact() if _option_tag(reader) else None
        pallet_index = reader.read_u8()

        if calls_ty is not None:
            pending_calls.append((pallet_name, pallet_index, calls_ty))
        if error_ty is not None:
            pending_errors.append((pallet_name, pallet_index, error_ty))

    return storage, pending_calls, pending_errors


def _read_storage_entry_value_type(reader: _Reader) -> int:
    tag = reader.read_u8()
    if tag == 0:
        return reader.read_compact()
    if tag == 1:
        n = reader.read_compact()
        for _ in range(n):
            reader.read_u8()
        reader.read_compact()
        return reader.read_compact()
    raise ScaleError(f"unknown StorageEntryType tag {tag}")


def _option_tag(reader: _Reader) -> bool:
    tag = reader.read_u8()
    if tag == 0:
        return False
    if tag == 1:
        return True
    raise ScaleError(f"invalid Option tag {tag}")


def _skip_optional_compact(reader: _Reader) -> None:
    if _option_tag(reader):
        reader.read_compact()


def _build_error_table(
    registry: tuple[_TypeShape, ...], pending: list[tuple[str, int, int]]
) -> ErrorTable:
    table = ErrorTable()
    for pallet_name, pallet_idx, error_ty in pending:
        if error_ty < 0 or error_ty >= len(registry):
            continue
        shape = registry[error_ty]
        if not isinstance(shape, _Variant):
            continue
        for variant_idx, variant_name, doc in shape.entries:
            table.by_idx[(pallet_idx, variant_idx)] = ErrorEntry(
                pallet=pallet_name,
                variant=variant_name,
                doc=doc,
            )
    return table


def _resolve_call_indices(
    registry: tuple[_TypeShape, ...], pending: list[tuple[str, int, int]]
) -> dict[tuple[str, str], tuple[int, int]]:
    out: dict[tuple[str, str], tuple[int, int]] = {}
    for pallet_name, pallet_idx, calls_ty in pending:
        if calls_ty < 0 or calls_ty >= len(registry):
            continue
        shape = registry[calls_ty]
        if not isinstance(shape, _Variant):
            continue
        for entry in shape.entries:
            call_idx, call_name = entry[0], entry[1]
            out[(pallet_name, call_name)] = (pallet_idx, call_idx)
    return out
