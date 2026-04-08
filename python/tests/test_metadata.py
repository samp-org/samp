from __future__ import annotations

from pathlib import Path

import pytest

from samp.metadata import (
    ErrorTable,
    FieldNotFoundError,
    Metadata,
    ScaleError,
    StorageNotFoundError,
)

E2E = Path(__file__).resolve().parent.parent.parent / "e2e"


def polkadot_metadata_bytes() -> bytes:
    raw = (E2E / "fixtures" / "polkadot_metadata_v14.scale").read_bytes()
    return b"meta" + raw


def test_from_runtime_metadata_rejects_empty_input():
    with pytest.raises(ScaleError):
        Metadata.from_runtime_metadata(b"")


def test_from_runtime_metadata_rejects_wrong_magic():
    with pytest.raises(ScaleError, match="magic"):
        Metadata.from_runtime_metadata(b"\x00\x00\x00\x00\x0e")


def test_from_runtime_metadata_rejects_wrong_version():
    with pytest.raises(ScaleError, match="version"):
        Metadata.from_runtime_metadata(b"meta\x0d")


def test_from_runtime_metadata_rejects_truncated_after_magic():
    with pytest.raises(ScaleError):
        Metadata.from_runtime_metadata(b"meta")


def test_parses_real_polkadot_v14_metadata():
    Metadata.from_runtime_metadata(polkadot_metadata_bytes())


def test_polkadot_metadata_resolves_system_account_data_free_layout():
    metadata = Metadata.from_runtime_metadata(polkadot_metadata_bytes())
    layout = metadata.storage_layout("System", "Account", ["data", "free"])
    assert layout.width in (8, 16)


def test_polkadot_metadata_finds_system_remark_call_index():
    metadata = Metadata.from_runtime_metadata(polkadot_metadata_bytes())
    result = metadata.find_call_index("System", "remark")
    assert result is not None
    pallet_idx, _ = result
    assert pallet_idx == 0


def test_polkadot_metadata_finds_system_remark_with_event_call_index():
    metadata = Metadata.from_runtime_metadata(polkadot_metadata_bytes())
    assert metadata.find_call_index("System", "remark_with_event") is not None


def test_storage_layout_returns_error_for_unknown_pallet():
    metadata = Metadata.from_runtime_metadata(polkadot_metadata_bytes())
    with pytest.raises(StorageNotFoundError):
        metadata.storage_layout("DoesNotExist", "Foo", ["bar"])


def test_storage_layout_returns_error_for_unknown_field():
    metadata = Metadata.from_runtime_metadata(polkadot_metadata_bytes())
    with pytest.raises(FieldNotFoundError):
        metadata.storage_layout("System", "Account", ["data", "nonexistent_field"])


def test_find_call_index_returns_none_for_unknown_call():
    metadata = Metadata.from_runtime_metadata(polkadot_metadata_bytes())
    assert metadata.find_call_index("System", "definitely_not_a_call") is None


def test_humanize_rpc_error_passes_through_unparseable_input():
    table = ErrorTable()
    assert table.humanize_rpc_error("not json at all") == "not json at all"


def test_humanize_rpc_error_extracts_data_field_from_rpc_error_envelope():
    table = ErrorTable()
    raw = (
        'RPC error: {"code":1010,"data":"Transaction has a bad signature","message":"Invalid"}'
    )
    assert table.humanize_rpc_error(raw) == "Transaction has a bad signature"


def test_humanize_rpc_error_falls_back_to_message_field():
    table = ErrorTable()
    raw = 'RPC error: {"code":1010,"message":"Invalid Transaction"}'
    assert table.humanize_rpc_error(raw) == "Invalid Transaction"


def test_humanize_returns_none_for_unknown_pair():
    table = ErrorTable()
    assert table.humanize(99, 99) is None


def test_storage_layout_decode_uint_round_trip():
    metadata = Metadata.from_runtime_metadata(polkadot_metadata_bytes())
    layout = metadata.storage_layout("System", "Account", ["data", "free"])
    value = 12345678
    fake_account = bytearray(layout.offset + layout.width + 16)
    fake_account[layout.offset : layout.offset + layout.width] = value.to_bytes(
        layout.width, "little"
    )
    assert layout.decode_uint(bytes(fake_account)) == value
