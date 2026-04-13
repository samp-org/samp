use samp::extrinsic::{build_signed_extrinsic, extract_call, extract_signer, ChainParams};
use samp::scale::encode_compact;
use samp::{
    CallArgs, CallIdx, ExtrinsicBytes, ExtrinsicNonce, GenesisHash, PalletIdx, Pubkey, Signature,
    SpecVersion, TxVersion,
};

use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct ExtrinsicVectors {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    label: String,
    pallet_idx: u8,
    call_idx: u8,
    call_args: String,
    public_key: String,
    fixed_signature: String,
    nonce: u32,
    chain_params: ChainParamsCase,
    expected_extrinsic: String,
}

#[derive(Deserialize)]
struct ChainParamsCase {
    genesis_hash: String,
    spec_version: u32,
    tx_version: u32,
}

const EXTRINSIC_VECTORS_JSON: &str = include_str!("../../e2e/extrinsic-vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("hex")
}

fn unhex_array<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("array length")
}

const ALICE_SEED: [u8; 32] = [0xAA; 32];

fn alice_keypair() -> schnorrkel::Keypair {
    MiniSecretKey::from_bytes(&ALICE_SEED)
        .unwrap()
        .expand_to_keypair(ExpansionMode::Ed25519)
}

fn substrate_sign(kp: &schnorrkel::Keypair, msg: &[u8]) -> Signature {
    let context = schnorrkel::signing_context(b"substrate");
    Signature::from_bytes(kp.sign(context.bytes(msg)).to_bytes())
}

fn test_chain_params() -> ChainParams {
    ChainParams::new(
        GenesisHash::from_bytes([0x11; 32]),
        SpecVersion::new(100),
        TxVersion::new(1),
    )
}

fn alice_pubkey(kp: &schnorrkel::Keypair) -> Pubkey {
    Pubkey::from_bytes(kp.public.to_bytes())
}

fn build_remark_args(remark: &[u8]) -> CallArgs {
    let mut args = Vec::new();
    encode_compact(remark.len() as u64, &mut args);
    args.extend_from_slice(remark);
    CallArgs::from_bytes(args)
}

#[test]
fn build_signed_extrinsic_round_trips_through_extract() {
    let kp = alice_keypair();
    let public_key = alice_pubkey(&kp);
    let remark = b"hello bob";
    let args = build_remark_args(remark);

    let ext = build_signed_extrinsic(
        PalletIdx::new(0),
        CallIdx::new(7),
        &args,
        &public_key,
        |msg| substrate_sign(&kp, msg),
        ExtrinsicNonce::new(0),
        &test_chain_params(),
    )
    .unwrap();

    let signer = extract_signer(&ext).expect("signer should extract");
    assert_eq!(signer.as_bytes(), public_key.as_bytes());

    let extracted = extract_call(&ext).expect("call should extract");
    assert_eq!(extracted.pallet().get(), 0);
    assert_eq!(extracted.call().get(), 7);
    assert_eq!(extracted.args().as_bytes(), args.as_bytes());
}

#[test]
fn build_signed_extrinsic_starts_with_compact_length_prefix() {
    let kp = alice_keypair();
    let public_key = alice_pubkey(&kp);
    let args = build_remark_args(b"x");

    let ext = build_signed_extrinsic(
        PalletIdx::new(0),
        CallIdx::new(7),
        &args,
        &public_key,
        |msg| substrate_sign(&kp, msg),
        ExtrinsicNonce::new(0),
        &test_chain_params(),
    )
    .unwrap();

    let (declared_len, prefix_len) =
        samp::scale::decode_compact(ext.as_bytes()).expect("compact length prefix");
    assert_eq!(
        usize::try_from(declared_len).unwrap() + prefix_len,
        ext.len()
    );
}

#[test]
fn build_signed_extrinsic_uses_immortal_era_byte() {
    let kp = alice_keypair();
    let public_key = alice_pubkey(&kp);
    let args = build_remark_args(b"x");

    let ext = build_signed_extrinsic(
        PalletIdx::new(0),
        CallIdx::new(7),
        &args,
        &public_key,
        |msg| substrate_sign(&kp, msg),
        ExtrinsicNonce::new(0),
        &test_chain_params(),
    )
    .unwrap();

    let (_, prefix_len) = samp::scale::decode_compact(ext.as_bytes()).unwrap();
    let payload = &ext.as_bytes()[prefix_len..];
    let era_offset = 1 + 1 + 32 + 1 + 64;
    assert_eq!(payload[era_offset], 0x00);
}

#[test]
fn build_signed_extrinsic_different_nonces_produce_different_bytes() {
    let kp = alice_keypair();
    let public_key = alice_pubkey(&kp);
    let args = build_remark_args(b"x");
    let cp = test_chain_params();

    let a = build_signed_extrinsic(
        PalletIdx::new(0),
        CallIdx::new(7),
        &args,
        &public_key,
        |msg| substrate_sign(&kp, msg),
        ExtrinsicNonce::new(0),
        &cp,
    )
    .unwrap();
    let b = build_signed_extrinsic(
        PalletIdx::new(0),
        CallIdx::new(7),
        &args,
        &public_key,
        |msg| substrate_sign(&kp, msg),
        ExtrinsicNonce::new(1),
        &cp,
    )
    .unwrap();

    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn extract_signer_returns_none_for_unsigned_extrinsic() {
    let unsigned = ExtrinsicBytes::from_bytes(vec![0x10, 0x04, 0x03, 0x00, 0x00]);
    assert!(extract_signer(&unsigned).is_none());
}

#[test]
fn extract_call_returns_none_for_unsigned_extrinsic() {
    let unsigned = ExtrinsicBytes::from_bytes(vec![0x10, 0x04, 0x03, 0x00, 0x00]);
    assert!(extract_call(&unsigned).is_none());
}

#[test]
fn extract_signer_returns_none_for_empty_input() {
    assert!(extract_signer(&ExtrinsicBytes::from_bytes(Vec::new())).is_none());
}

#[test]
fn matches_e2e_extrinsic_vectors_fixture() {
    let vectors: ExtrinsicVectors =
        serde_json::from_str(EXTRINSIC_VECTORS_JSON).expect("parse fixture");
    for case in vectors.cases {
        let public_key = Pubkey::from_bytes(unhex_array(&case.public_key));
        let signature = Signature::from_bytes(unhex_array(&case.fixed_signature));
        let call_args = CallArgs::from_bytes(unhex(&case.call_args));
        let chain = ChainParams::new(
            GenesisHash::from_bytes(unhex_array(&case.chain_params.genesis_hash)),
            SpecVersion::new(case.chain_params.spec_version),
            TxVersion::new(case.chain_params.tx_version),
        );

        let built = build_signed_extrinsic(
            PalletIdx::new(case.pallet_idx),
            CallIdx::new(case.call_idx),
            &call_args,
            &public_key,
            |_msg| signature,
            ExtrinsicNonce::new(case.nonce),
            &chain,
        )
        .unwrap();

        assert_eq!(
            built.as_bytes(),
            unhex(&case.expected_extrinsic).as_slice(),
            "case {} did not match fixture",
            case.label
        );
    }
}

#[test]
fn build_signed_extrinsic_payload_above_256_bytes_uses_blake2_hash() {
    let kp = alice_keypair();
    let public_key = alice_pubkey(&kp);
    let big_remark = vec![0xAB; 1024];
    let args = build_remark_args(&big_remark);

    let ext = build_signed_extrinsic(
        PalletIdx::new(0),
        CallIdx::new(7),
        &args,
        &public_key,
        |msg| {
            assert_eq!(msg.len(), 32, "long payload should be hashed to 32 bytes");
            substrate_sign(&kp, msg)
        },
        ExtrinsicNonce::new(0),
        &test_chain_params(),
    )
    .unwrap();

    let extracted = extract_call(&ext).unwrap();
    assert_eq!(extracted.args().as_bytes(), args.as_bytes());
}
