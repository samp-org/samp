use samp::metadata::{Error, ErrorTable, Metadata};

const POLKADOT_V14_RAW: &[u8] = include_bytes!("../../e2e/fixtures/polkadot_metadata_v14.scale");

fn polkadot_metadata_bytes() -> Vec<u8> {
    let mut full = Vec::with_capacity(POLKADOT_V14_RAW.len() + 4);
    full.extend_from_slice(b"meta");
    full.extend_from_slice(POLKADOT_V14_RAW);
    full
}

#[test]
fn from_runtime_metadata_rejects_empty_input() {
    let err = Metadata::from_runtime_metadata(&[]).unwrap_err();
    assert!(matches!(err, Error::Scale(_)));
}

#[test]
fn from_runtime_metadata_rejects_wrong_magic() {
    let bytes = [0x00, 0x00, 0x00, 0x00, 14u8];
    let err = Metadata::from_runtime_metadata(&bytes).unwrap_err();
    assert!(matches!(err, Error::Scale(s) if s.contains("magic")));
}

#[test]
fn from_runtime_metadata_rejects_wrong_version() {
    let mut bytes = vec![0x6du8, 0x65, 0x74, 0x61];
    bytes.push(13);
    let err = Metadata::from_runtime_metadata(&bytes).unwrap_err();
    assert!(matches!(err, Error::Scale(s) if s.contains("version") && s.contains("13")));
}

#[test]
fn from_runtime_metadata_rejects_truncated_after_magic() {
    let bytes = vec![0x6du8, 0x65, 0x74, 0x61];
    let err = Metadata::from_runtime_metadata(&bytes).unwrap_err();
    assert!(matches!(err, Error::Scale(_)));
}

#[test]
fn parses_real_polkadot_v14_metadata() {
    let metadata = Metadata::from_runtime_metadata(&polkadot_metadata_bytes())
        .expect("frontier metadata should parse");
    let _ = metadata;
}

#[test]
fn polkadot_metadata_resolves_system_account_data_free_layout() {
    let metadata = Metadata::from_runtime_metadata(&polkadot_metadata_bytes()).unwrap();
    let layout = metadata
        .storage_layout("System", "Account", &["data", "free"])
        .expect("System.Account.data.free should resolve");
    assert!(
        layout.width == 8 || layout.width == 16,
        "expected u64 or u128 free balance, got width {}",
        layout.width
    );
}

#[test]
fn polkadot_metadata_finds_system_remark_call_index() {
    let metadata = Metadata::from_runtime_metadata(&polkadot_metadata_bytes()).unwrap();
    let (pallet_idx, call_idx) = metadata
        .find_call_index("System", "remark")
        .expect("System.remark must exist on a FRAME chain");
    assert_eq!(pallet_idx, 0, "System pallet conventionally at index 0");
    let _ = call_idx;
}

#[test]
fn polkadot_metadata_finds_system_remark_with_event_call_index() {
    let metadata = Metadata::from_runtime_metadata(&polkadot_metadata_bytes()).unwrap();
    let result = metadata.find_call_index("System", "remark_with_event");
    assert!(result.is_some(), "System.remark_with_event must exist");
}

#[test]
fn storage_layout_returns_error_for_unknown_pallet() {
    let metadata = Metadata::from_runtime_metadata(&polkadot_metadata_bytes()).unwrap();
    let err = metadata
        .storage_layout("DoesNotExist", "Foo", &["bar"])
        .unwrap_err();
    assert!(matches!(err, Error::StorageNotFound { .. }));
}

#[test]
fn storage_layout_returns_error_for_unknown_field() {
    let metadata = Metadata::from_runtime_metadata(&polkadot_metadata_bytes()).unwrap();
    let err = metadata
        .storage_layout("System", "Account", &["data", "nonexistent_field"])
        .unwrap_err();
    assert!(matches!(err, Error::FieldNotFound { .. }));
}

#[test]
fn find_call_index_returns_none_for_unknown_call() {
    let metadata = Metadata::from_runtime_metadata(&polkadot_metadata_bytes()).unwrap();
    assert!(metadata
        .find_call_index("System", "definitely_not_a_call")
        .is_none());
}

#[test]
fn humanize_rpc_error_passes_through_unparseable_input() {
    let table = ErrorTable::default();
    assert_eq!(
        table.humanize_rpc_error("not json at all"),
        "not json at all"
    );
}

#[test]
fn humanize_rpc_error_extracts_data_field_from_rpc_error_envelope() {
    let table = ErrorTable::default();
    let raw =
        r#"RPC error: {"code":1010,"data":"Transaction has a bad signature","message":"Invalid"}"#;
    assert_eq!(
        table.humanize_rpc_error(raw),
        "Transaction has a bad signature"
    );
}

#[test]
fn humanize_rpc_error_falls_back_to_message_field() {
    let table = ErrorTable::default();
    let raw = r#"RPC error: {"code":1010,"message":"Invalid Transaction"}"#;
    assert_eq!(table.humanize_rpc_error(raw), "Invalid Transaction");
}

#[test]
fn humanize_returns_none_for_unknown_pair() {
    let table = ErrorTable::default();
    assert!(table.humanize(99, 99).is_none());
}
