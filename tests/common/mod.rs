#![allow(dead_code)]

use ckb_idl_client::types::{IdlDocument, SigningInfo, WitnessField};
use proptest::prelude::*;

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
        })
}

pub fn arb_signing_info() -> impl Strategy<Value = SigningInfo> {
    (arb_string(), arb_string(), arb_string()).prop_map(|(algorithm, message, hasher)| {
        SigningInfo {
            algorithm,
            message,
            hasher,
        }
    })
}

pub fn arb_idl_document() -> impl Strategy<Value = IdlDocument> {
    (
        arb_string(),
        arb_string(),
        proptest::collection::vec(arb_witness_field(), 0..10),
        proptest::option::of(arb_string()),
        proptest::option::of(arb_string()),
        proptest::option::of(arb_signing_info()),
    )
        .prop_map(
            |(idl_version, name, witness, description, script_version, signing)| IdlDocument {
                idl_version,
                name,
                witness,
                description,
                script_version,
                signing,
            },
        )
}
