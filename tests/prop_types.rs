mod common;

use proptest::prelude::*;

// Property 1: IdlDocument serialization round-trip
// For any valid IdlDocument, serializing to JSON and deserializing must produce
// an equal value.
// Validates: Requirements 1.10, 1.1, 1.6, 1.9
proptest! {
    #[test]
    fn prop_idl_document_round_trip(doc in common::arb_idl_document()) {
        let bytes = serde_json::to_vec(&doc).unwrap();
        let restored: ckb_idl_client::IdlDocument = serde_json::from_slice(&bytes).unwrap();
        prop_assert_eq!(doc, restored);
    }
}
