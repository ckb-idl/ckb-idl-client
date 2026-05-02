mod common;

use ckb_idl_client::{IdlClient, IdlError};
use proptest::prelude::*;

/// Compute blake2b-256 (32-byte output) — must match the implementation in client.rs
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

// Property 2: Verify succeeds when hash matches.
// For any valid IdlDocument and any prefix bytes, constructing code_cell_data
// as prefix ++ blake2b_256(idl_json) must make verify return Ok(()).
// Validates: Requirements 3.1, 3.2, 3.3
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn prop_verify_succeeds_on_correct_hash(
        doc in common::arb_idl_document(),
        prefix in proptest::collection::vec(any::<u8>(), 0..100),
        code_hash in proptest::array::uniform32(any::<u8>()),
    ) {
        let idl_json_bytes = serde_json::to_vec(&doc).unwrap();
        let hash = blake2b_256(&idl_json_bytes);

        let mut code_cell_data = prefix;
        code_cell_data.extend_from_slice(&hash);

        let mut client = IdlClient::new();
        let result = client.verify(code_hash, &idl_json_bytes, &code_cell_data);
        prop_assert!(result.is_ok());
    }
}

// Property 3: Verify fails on hash mismatch.
// For any valid IdlDocument and any wrong_hash that differs from the real hash,
// verify must return Err(IdlError::HashMismatch).
// Validates: Requirement 3.4
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn prop_verify_fails_on_hash_mismatch(
        doc in common::arb_idl_document(),
        wrong_hash in proptest::array::uniform32(any::<u8>()),
        code_hash in proptest::array::uniform32(any::<u8>()),
    ) {
        let idl_json_bytes = serde_json::to_vec(&doc).unwrap();
        let real_hash = blake2b_256(&idl_json_bytes);

        // Filter out the (astronomically unlikely) case where wrong_hash == real hash
        proptest::prop_assume!(wrong_hash != real_hash);

        // Build code_cell_data with the wrong hash as the last 32 bytes
        let mut code_cell_data = vec![0u8; 64];
        code_cell_data[32..].copy_from_slice(&wrong_hash);

        let mut client = IdlClient::new();
        let result = client.verify(code_hash, &idl_json_bytes, &code_cell_data);

        prop_assert!(
            matches!(result, Err(IdlError::HashMismatch { .. })),
            "expected HashMismatch, got {:?}",
            result
        );
    }
}

// Property 4: Verify fails on insufficient code cell data.
// For any code_cell_data shorter than 32 bytes, verify must return
// Err(IdlError::InsufficientData { actual }) where actual == data.len().
// Validates: Requirement 3.5
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn prop_verify_fails_on_insufficient_data(
        short_data in proptest::collection::vec(any::<u8>(), 0..32),
        idl_bytes in proptest::collection::vec(any::<u8>(), 0..100),
        code_hash in proptest::array::uniform32(any::<u8>()),
    ) {
        let expected_len = short_data.len();
        let mut client = IdlClient::new();
        let result = client.verify(code_hash, &idl_bytes, &short_data);

        prop_assert!(
            matches!(result, Err(IdlError::InsufficientData { actual }) if actual == expected_len),
            "expected InsufficientData {{ actual: {} }}, got {:?}",
            expected_len,
            result
        );
    }
}
