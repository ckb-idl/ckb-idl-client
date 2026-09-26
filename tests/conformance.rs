use ckb_idl_client::types::EncodingProfile;
use ckb_idl_client::{
    DecodedValue, IdlClient, IdlDocument, IdlInterface, InterfaceKind, WitnessField, WitnessObject,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/idl-0.1.0")
}

fn read_json(path: impl AsRef<Path>) -> Value {
    let bytes = std::fs::read(path).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn document(fields: Vec<WitnessField>) -> IdlDocument {
    IdlDocument {
        idl_version: "0.1.0".to_string(),
        interfaces: vec![IdlInterface {
            id: "lock_witness".to_string(),
            kind: InterfaceKind::WitnessArgsLock,
            encoding: EncodingProfile {
                id: "ckb-idl-linear-0.1.0".to_string(),
            },
            fields,
        }],
    }
}

fn decode_hex(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn object_json(object: &WitnessObject) -> Value {
    let mut result = Map::new();
    for field in object {
        result.insert(field.name.clone(), value_json(&field.value));
    }
    Value::Object(result)
}

fn value_json(value: &DecodedValue) -> Value {
    match value {
        DecodedValue::Bytes(bytes) => Value::String(format!("0x{}", hex::encode(bytes))),
        DecodedValue::U8(value) => json!(value),
        DecodedValue::U16(value) => json!(value),
        DecodedValue::U32(value) => json!(value),
        DecodedValue::U64(value) => Value::String(value.to_string()),
        DecodedValue::U128(value) => Value::String(value.to_string()),
        DecodedValue::Vector(values) => Value::Array(values.iter().map(value_json).collect()),
        DecodedValue::Struct(object) => object_json(object),
        DecodedValue::Union {
            tag,
            variant,
            value,
        } => json!({
            "$tag": tag,
            "$variant": variant,
            "value": object_json(value),
        }),
        DecodedValue::Optional(None) => Value::Null,
        DecodedValue::Optional(Some(value)) => value_json(value),
    }
}

fn binding_trailer(idl_bytes: &[u8]) -> Vec<u8> {
    let mut data = b"executable".to_vec();
    data.push(1);
    data.push(0);
    data.extend_from_slice(&Sha256::digest(idl_bytes));
    data.extend_from_slice(&34u32.to_le_bytes());
    data.extend_from_slice(b"CKBIDL\0\0");
    data
}

fn assert_error(error: &ckb_idl_client::IdlError, expected: &Value, vector: &str) {
    assert_eq!(
        error.category(),
        expected["kind"].as_str().unwrap(),
        "[{vector}] category mismatch: {error:?}"
    );
    assert_eq!(
        error.path(),
        expected["path"].as_str().unwrap(),
        "[{vector}] path mismatch: {error:?}"
    );
}

#[test]
fn passes_normative_valid_vectors_and_reencodes_exact_bytes() {
    let root = read_json(fixture_root().join("test-vectors/valid.json"));
    let client = IdlClient::new();

    for vector in root["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let fields: Vec<WitnessField> = serde_json::from_value(vector["fields"].clone()).unwrap();
        let wire = decode_hex(&vector["wire_hex"]);
        let object = client.validate_witness_bytes(&fields, &wire).unwrap();

        assert_eq!(
            object_json(&object),
            vector["expected_object"],
            "[{name}] decoded object mismatch"
        );
        assert_eq!(
            client
                .encode_lock_witness(&document(fields), &object)
                .unwrap(),
            wire,
            "[{name}] re-encoded bytes mismatch"
        );
    }
}

#[test]
fn passes_normative_malformed_wire_vectors() {
    let root = read_json(fixture_root().join("test-vectors/malformed.json"));
    let client = IdlClient::new();

    for vector in root["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let fields: Vec<WitnessField> = serde_json::from_value(vector["fields"].clone()).unwrap();
        let wire = decode_hex(&vector["wire_hex"]);
        let error = client.validate_witness_bytes(&fields, &wire).unwrap_err();
        assert_error(&error, &vector["expected_error"], name);
    }
}

#[test]
fn nested_decode_errors_use_logical_object_paths() {
    let client = IdlClient::new();

    let struct_fields: Vec<WitnessField> = serde_json::from_value(json!([{
        "name": "inner",
        "required": true,
        "type": "struct",
        "fields": [{ "name": "nonce", "required": true, "type": "uint64" }]
    }]))
    .unwrap();
    let error = client
        .validate_witness_bytes(&struct_fields, &[])
        .unwrap_err();
    assert_eq!(error.category(), "field_too_short");
    assert_eq!(error.path(), "/inner/nonce");

    let union_fields: Vec<WitnessField> = serde_json::from_value(json!([{
        "name": "authorization",
        "required": true,
        "type": "union",
        "variants": [{
            "tag": 1,
            "name": "Nonce",
            "fields": [{ "name": "nonce", "required": true, "type": "uint64" }]
        }]
    }]))
    .unwrap();
    let error = client
        .validate_witness_bytes(&union_fields, &1u32.to_le_bytes())
        .unwrap_err();
    assert_eq!(error.category(), "field_too_short");
    assert_eq!(error.path(), "/authorization/value/nonce");
}

#[test]
fn passes_normative_malformed_document_vectors() {
    let root = read_json(fixture_root().join("test-vectors/malformed-documents.json"));

    for vector in root["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let fields = vector
            .get("fields")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![vector["field"].clone()]));
        let value = json!({
            "idl_version": "0.1.0",
            "interfaces": [{
                "id": "lock_witness",
                "kind": "witness_args.lock",
                "encoding": { "id": "ckb-idl-linear-0.1.0" },
                "fields": fields,
            }],
        });
        let bytes = serde_json::to_vec(&value).unwrap();
        let error = match IdlClient::parse_document(&bytes) {
            Ok(document) => document.validate().unwrap_err(),
            Err(error) => error,
        };
        assert_error(&error, &vector["expected_error"], name);
    }
}

#[test]
fn passes_normative_canonicalization_vectors() {
    let vector_dir = fixture_root().join("test-vectors");
    let root = read_json(vector_dir.join("canonicalization.json"));

    for vector in root["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let bytes = if let Some(file) = vector.get("file") {
            std::fs::read(vector_dir.join(file.as_str().unwrap())).unwrap()
        } else if let Some(text) = vector.get("text") {
            text.as_str().unwrap().as_bytes().to_vec()
        } else {
            decode_hex(&vector["bytes_hex"])
        };
        let trailer = binding_trailer(&bytes);
        let result = IdlClient::verify_commitment(&bytes, &trailer);

        if vector["expected"] == "canonical" {
            result.unwrap();
        } else {
            assert_error(&result.unwrap_err(), &vector["expected_error"], name);
        }
    }
}

#[test]
fn passes_normative_flat_bytes_vector() {
    let vector_dir = fixture_root().join("test-vectors");
    let vector = read_json(vector_dir.join("flat-bytes.json"));
    let idl_bytes = std::fs::read(vector_dir.join(vector["idl_file"].as_str().unwrap())).unwrap();
    let document = IdlClient::parse_document(&idl_bytes).unwrap();
    let wire = decode_hex(&vector["wire_hex"]);
    let object = IdlClient::new()
        .decode_lock_witness(&document, &wire)
        .unwrap();
    assert_eq!(object_json(&object), vector["expected_object"]);
}

#[test]
fn document_parser_rejects_trailing_input() {
    let mut bytes = std::fs::read(fixture_root().join("examples/flat-witness.json")).unwrap();
    bytes.extend_from_slice(b"{}");

    let error = IdlClient::parse_document(&bytes).unwrap_err();
    assert_eq!(error.category(), "invalid_document");
    assert_eq!(error.path(), "");
}

#[test]
fn canonical_example_hashes_match_manifest() {
    let root = fixture_root();
    let manifest = read_json(root.join("canonicalization-fixtures.json"));

    for fixture in manifest["fixtures"].as_array().unwrap() {
        let bytes = std::fs::read(root.join(fixture["file"].as_str().unwrap())).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            fixture["sha256"].as_str().unwrap()
        );
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json_canonicalizer::to_vec(&parsed).unwrap(), bytes);
        IdlClient::parse_document(&bytes)
            .unwrap()
            .validate()
            .unwrap();
    }
}
