#![allow(dead_code)]

use ckb_idl_client::{
    IdlInterface, InterfaceKind,
    types::{EncodingProfile, IdlDocument, WitnessField},
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

// Use printable ASCII strings to avoid JSON serialization edge cases with
// arbitrary Unicode (lone surrogates, null bytes, etc.)
fn arb_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_\\-\\.]{0,32}".prop_map(|s| s.to_string())
}

pub fn arb_witness_field() -> impl Strategy<Value = WitnessField> {
    (
        arb_string(),
        arb_string(),
        any::<bool>(),
        proptest::option::of(arb_string()),
    )
        .prop_map(|(name, type_, required, description)| WitnessField {
            name,
            type_,
            required,
            description,
            items: None,
            fields: None,
            variants: None,
            wire_type: None,
        })
}

pub fn arb_idl_document() -> impl Strategy<Value = IdlDocument> {
    proptest::collection::vec(arb_witness_field(), 0..10).prop_map(|witness| IdlDocument {
        idl_version: "0.1.0".to_string(),
        interfaces: vec![IdlInterface {
            id: "lock_witness".to_string(),
            kind: InterfaceKind::WitnessArgsLock,
            encoding: EncodingProfile {
                id: "ckb-idl-linear-0.1.0".to_string(),
            },
            fields: witness,
        }],
    })
}

pub fn canonical_bytes(document: &IdlDocument) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(document).unwrap()
}

pub fn trailer_one(idl_bytes: &[u8], digest: Option<[u8; 32]>, prefix: &[u8]) -> Vec<u8> {
    let hash = digest.unwrap_or_else(|| Sha256::digest(idl_bytes).into());
    let mut data = prefix.to_vec();
    data.push(1);
    data.push(0);
    data.extend_from_slice(&hash);
    data.extend_from_slice(&34u32.to_le_bytes());
    data.extend_from_slice(b"CKBIDL\0\0");
    data
}
