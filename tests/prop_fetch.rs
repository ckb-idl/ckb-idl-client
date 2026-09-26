mod common;

use ckb_idl_client::types::EncodingProfile;
use ckb_idl_client::{IdlClient, IdlDocument, IdlError, IdlInterface, InterfaceKind, WitnessField};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn valid_document() -> IdlDocument {
    IdlDocument {
        idl_version: "0.1.0".to_string(),
        interfaces: vec![IdlInterface {
            id: "lock_witness".to_string(),
            kind: InterfaceKind::WitnessArgsLock,
            encoding: EncodingProfile {
                id: "ckb-idl-linear-0.1.0".to_string(),
            },
            fields: vec![WitnessField {
                name: "signature".to_string(),
                type_: "secp256k1_sig".to_string(),
                wire_type: Some("bytes_fixed_65".to_string()),
                required: true,
                description: Some("65-byte ECDSA signature".to_string()),
                items: None,
                fields: None,
                variants: None,
            }],
        }],
    }
}

#[tokio::test]
async fn fetch_bytes_preserves_exact_response_bytes() {
    let code_hash = [0x42u8; 32];
    let expected_path = format!("/idl/{}", hex::encode(code_hash));
    let body = common::canonical_bytes(&valid_document());
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(&expected_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&mock_server)
        .await;

    let client = IdlClient::new();
    assert_eq!(
        client
            .fetch_bytes(&mock_server.uri(), code_hash)
            .await
            .unwrap(),
        body
    );
}

#[tokio::test]
async fn fetch_verify_and_cache_exposes_only_verified_requirements() {
    let document = valid_document();
    let idl_bytes = common::canonical_bytes(&document);
    let code_cell_data = common::trailer_one(&idl_bytes, None, b"executable");
    let code_hash = [0x43u8; 32];
    let expected_path = format!("/idl/{}", hex::encode(code_hash));
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(&expected_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(idl_bytes))
        .mount(&mock_server)
        .await;

    let mut client = IdlClient::new();
    client
        .fetch_verify_and_cache(&mock_server.uri(), code_hash, &code_cell_data)
        .await
        .unwrap();

    assert_eq!(
        client.lock_witness_requirements(code_hash).unwrap(),
        document.lock_witness().unwrap().fields
    );
}

#[tokio::test]
async fn fetch_verify_and_cache_rejects_invalid_document() {
    let document = IdlDocument {
        idl_version: "0.1.0".to_string(),
        interfaces: vec![],
    };
    let idl_bytes = common::canonical_bytes(&document);
    let code_cell_data = common::trailer_one(&idl_bytes, None, b"executable");
    let code_hash = [0x01u8; 32];
    let expected_path = format!("/idl/{}", hex::encode(code_hash));
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(&expected_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(idl_bytes))
        .mount(&mock_server)
        .await;

    let mut client = IdlClient::new();
    let result = client
        .fetch_verify_and_cache(&mock_server.uri(), code_hash, &code_cell_data)
        .await;
    assert!(matches!(result, Err(IdlError::MissingLockWitnessInterface)));
    assert!(matches!(
        client.lock_witness_requirements(code_hash),
        Err(IdlError::DocumentNotVerified { .. })
    ));
}

#[tokio::test]
async fn fetch_bytes_propagates_http_errors() {
    for &status_code in &[400, 404, 422, 500, 503] {
        let mock_server = MockServer::start().await;
        let code_hash = [0xFFu8; 32];
        let expected_path = format!("/idl/{}", hex::encode(code_hash));

        Mock::given(method("GET"))
            .and(path(&expected_path))
            .respond_with(ResponseTemplate::new(status_code))
            .mount(&mock_server)
            .await;

        let client = IdlClient::new();
        let result = client.fetch_bytes(&mock_server.uri(), code_hash).await;
        assert!(
            matches!(result, Err(IdlError::HttpError { status }) if status == status_code),
            "expected status {status_code}, got {result:?}"
        );
    }
}
