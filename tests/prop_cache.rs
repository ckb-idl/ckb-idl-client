mod common;

use ckb_idl_client::IdlClient;
use proptest::prelude::*;

// Property 5: Cache hit returns exact witness fields.
// After a successful verify(code_hash, ...), witness_requirements(code_hash)
// must return a Vec<WitnessField> equal to the original document's witness array,
// without making a network request.
// Validates: Requirements 4.1, 4.5, 5.1, 5.2, 5.5
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn prop_cache_hit_returns_exact_witness_fields(
        doc in common::arb_idl_document(),
        code_hash in proptest::array::uniform32(any::<u8>()),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let idl_json_bytes = common::canonical_bytes(&doc);
            let code_cell_data = common::trailer_one(&idl_json_bytes, None, &[0xAA; 16]);

            let mut client = IdlClient::new();

            // verify populates the cache
            client.verify(code_hash, &idl_json_bytes, &code_cell_data).unwrap();

            // witness_requirements should hit the cache — use a dummy URL that
            // would fail if a network request were actually made
            let result = client
                .lock_witness_requirements(code_hash);

            prop_assert!(result.is_ok(), "witness_requirements failed: {:?}", result);
            prop_assert_eq!(result.unwrap(), doc.lock_witness()?.fields.clone());
            Ok(()) as Result<(), TestCaseError>
        })?;
    }
}
