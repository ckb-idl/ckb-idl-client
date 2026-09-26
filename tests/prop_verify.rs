mod common;

use ckb_idl_client::{IdlClient, IdlError};
use proptest::prelude::*;
use sha2::Digest;

// Property 2: Verify succeeds when hash matches.
// For any valid IdlDocument and any prefix bytes, constructing code_cell_data
// as prefix ++ Binding Trailer 1 must make verify return Ok(()).
// Validates: Requirements 3.1, 3.2, 3.3
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn prop_verify_succeeds_on_correct_hash(
        doc in common::arb_idl_document(),
        prefix in proptest::collection::vec(any::<u8>(), 0..100),
        code_hash in proptest::array::uniform32(any::<u8>()),
    ) {
        let idl_json_bytes = common::canonical_bytes(&doc);
        let code_cell_data = common::trailer_one(&idl_json_bytes, None, &prefix);

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
        let idl_json_bytes = common::canonical_bytes(&doc);
        let real_hash: [u8; 32] = sha2::Sha256::digest(&idl_json_bytes).into();

        // Filter out the (astronomically unlikely) case where wrong_hash == real hash
        proptest::prop_assume!(wrong_hash != real_hash);

        let code_cell_data = common::trailer_one(&idl_json_bytes, Some(wrong_hash), &[0u8; 32]);

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
// For any code_cell_data shorter than the 46-byte trailer, verify must return
// Err(IdlError::InsufficientData { actual }) where actual == data.len().
// Validates: Requirement 3.5
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn prop_verify_fails_on_insufficient_data(
        short_data in proptest::collection::vec(any::<u8>(), 0..46),
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
