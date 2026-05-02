mod common;

use ckb_idl_client::{IdlClient, IdlError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Property 6: Fetch returns the document served by the indexer.
// When the mock indexer serves a valid IdlDocument JSON at GET /idl/{code_hash_hex},
// fetch must return an IdlDocument equal to the original.
// Validates: Requirements 2.1, 2.2
#[tokio::test]
async fn prop_fetch_returns_served_document() {
    // Use a fixed known-good document
    let doc = ckb_idl_client::IdlDocument {
        idl_version: "1".to_string(),
        name: "test_lock".to_string(),
        witness: vec![
            ckb_idl_client::WitnessField {
                name: "signature".to_string(),
                type_: "secp256k1_sig".to_string(),
                required: true,
                description: Some("65-byte ECDSA signature".to_string()),
            },
            ckb_idl_client::WitnessField {
                name: "pubkey".to_string(),
                type_: "bytes33".to_string(),
                required: false,
                description: None,
            },
        ],
        description: Some("A test lock script".to_string()),
        script_version: Some("1".to_string()),
        signing: None,
    };

    let code_hash = [0x42u8; 32];
    let code_hash_hex = hex::encode(code_hash);
    let expected_path = format!("/idl/{}", code_hash_hex);

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(&expected_path))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&doc),
        )
        .mount(&mock_server)
        .await;

    let client = IdlClient::new();
    let result = client.fetch(&mock_server.uri(), code_hash).await;

    assert!(result.is_ok(), "fetch failed: {:?}", result);
    assert_eq!(result.unwrap(), doc);
}

// Property 6b: Fetch works for an empty witness array.
#[tokio::test]
async fn prop_fetch_returns_document_with_empty_witness() {
    let doc = ckb_idl_client::IdlDocument {
        idl_version: "1".to_string(),
        name: "minimal_lock".to_string(),
        witness: vec![],
        description: None,
        script_version: None,
        signing: None,
    };

    let code_hash = [0x01u8; 32];
    let code_hash_hex = hex::encode(code_hash);
    let expected_path = format!("/idl/{}", code_hash_hex);

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(&expected_path))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&doc),
        )
        .mount(&mock_server)
        .await;

    let client = IdlClient::new();
    let result = client.fetch(&mock_server.uri(), code_hash).await;

    assert!(result.is_ok(), "fetch failed: {:?}", result);
    assert_eq!(result.unwrap().witness, vec![]);
}

// Property 7: Fetch propagates HTTP error status codes.
// When the indexer returns a 4xx or 5xx status, fetch must return
// Err(IdlError::HttpError { status }) with the matching status code.
// Validates: Requirement 2.3
#[tokio::test]
async fn prop_fetch_propagates_http_errors() {
    let error_statuses: &[u16] = &[400, 404, 422, 500, 503];

    for &status_code in error_statuses {
        let mock_server = MockServer::start().await;
        let code_hash = [0xFFu8; 32];
        let code_hash_hex = hex::encode(code_hash);
        let expected_path = format!("/idl/{}", code_hash_hex);

        Mock::given(method("GET"))
            .and(path(&expected_path))
            .respond_with(ResponseTemplate::new(status_code))
            .mount(&mock_server)
            .await;

        let client = IdlClient::new();
        let result = client.fetch(&mock_server.uri(), code_hash).await;

        assert!(
            matches!(result, Err(IdlError::HttpError { status }) if status == status_code),
            "expected HttpError {{ status: {} }}, got {:?}",
            status_code,
            result
        );
    }
}
