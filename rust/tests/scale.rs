use samp::scale::{decode_bytes, decode_compact, encode_compact};
use serde::Deserialize;

#[derive(Deserialize)]
struct ScaleVectors {
    compact: Vec<CompactCase>,
}

#[derive(Deserialize)]
struct CompactCase {
    value: u64,
    encoded: String,
    consumed: usize,
}

const SCALE_VECTORS_JSON: &str = include_str!("../../e2e/scale-vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("hex")
}

fn enc(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_compact(value, &mut out);
    out
}

fn dec(bytes: &[u8]) -> (u64, usize) {
    decode_compact(bytes).expect("decode")
}

#[test]
fn compact_mode_zero_at_lower_bound() {
    let bytes = enc(0);
    assert_eq!(bytes, vec![0x00]);
    assert_eq!(dec(&bytes), (0, 1));
}

#[test]
fn compact_mode_zero_at_upper_bound() {
    let bytes = enc(63);
    assert_eq!(bytes, vec![0xFC]);
    assert_eq!(dec(&bytes), (63, 1));
}

#[test]
fn compact_mode_one_at_lower_bound() {
    let bytes = enc(64);
    assert_eq!(bytes, vec![0x01, 0x01]);
    assert_eq!(dec(&bytes), (64, 2));
}

#[test]
fn compact_mode_one_at_upper_bound() {
    let bytes = enc(16_383);
    assert_eq!(dec(&bytes), (16_383, 2));
}

#[test]
fn compact_mode_two_at_lower_bound() {
    let bytes = enc(16_384);
    assert_eq!(dec(&bytes), (16_384, 4));
}

#[test]
fn compact_mode_two_at_upper_bound() {
    let bytes = enc((1 << 30) - 1);
    assert_eq!(dec(&bytes), ((1 << 30) - 1, 4));
}

#[test]
fn compact_big_int_mode_at_2_pow_30() {
    let bytes = enc(1 << 30);
    let (v, _) = dec(&bytes);
    assert_eq!(v, 1 << 30);
}

#[test]
fn compact_big_int_mode_u32_max() {
    let bytes = enc(u64::from(u32::MAX));
    let (v, _) = dec(&bytes);
    assert_eq!(v, u64::from(u32::MAX));
}

#[test]
fn compact_big_int_mode_u64_max() {
    let bytes = enc(u64::MAX);
    let (v, _) = dec(&bytes);
    assert_eq!(v, u64::MAX);
}

#[test]
fn compact_round_trip_across_all_modes() {
    let probes = [
        0u64,
        1,
        63,
        64,
        100,
        16_383,
        16_384,
        1 << 20,
        (1 << 30) - 1,
        1 << 30,
        1 << 32,
        u64::MAX,
    ];
    for &v in &probes {
        let mut buf = Vec::new();
        encode_compact(v, &mut buf);
        let (decoded, _) = decode_compact(&buf).unwrap();
        assert_eq!(decoded, v, "round-trip failed for {v}");
    }
}

#[test]
fn decode_compact_returns_none_on_empty_input() {
    assert!(decode_compact(&[]).is_none());
}

#[test]
fn decode_compact_returns_none_on_truncated_two_byte_mode() {
    assert!(decode_compact(&[0x01]).is_none());
}

#[test]
fn decode_compact_returns_none_on_truncated_four_byte_mode() {
    assert!(decode_compact(&[0x02, 0x00, 0x00]).is_none());
}

#[test]
fn decode_compact_returns_none_on_truncated_big_int_mode() {
    assert!(decode_compact(&[0x03, 0x01]).is_none());
}

#[test]
fn decode_bytes_extracts_payload_after_compact_length() {
    let mut wire = Vec::new();
    encode_compact(5, &mut wire);
    wire.extend_from_slice(b"hello");
    let (payload, consumed) = decode_bytes(&wire).unwrap();
    assert_eq!(payload, b"hello");
    assert_eq!(consumed, 6);
}

#[test]
fn decode_bytes_returns_none_when_payload_truncated() {
    let mut wire = Vec::new();
    encode_compact(10, &mut wire);
    wire.extend_from_slice(b"only5");
    assert!(decode_bytes(&wire).is_none());
}

#[test]
fn matches_e2e_scale_vectors_fixture() {
    let vectors: ScaleVectors = serde_json::from_str(SCALE_VECTORS_JSON).expect("parse fixture");
    for case in vectors.compact {
        let mut encoded = Vec::new();
        encode_compact(case.value, &mut encoded);
        assert_eq!(
            encoded,
            unhex(&case.encoded),
            "encode mismatch for {}",
            case.value
        );

        let (decoded, consumed) = decode_compact(&encoded).expect("decode round-trip");
        assert_eq!(decoded, case.value);
        assert_eq!(consumed, case.consumed);
    }
}
