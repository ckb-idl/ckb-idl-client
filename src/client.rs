use crate::{
    IdlDocument, IdlError, Result, WitnessField,
    types::{DecodedValue, ValidatedField},
};
use std::collections::HashMap;
use sha2::{Sha256, Digest};

/// Compute a 32-byte BLAKE2b-256 digest of the given bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Returns the expected fixed byte-size for a given IDL type string,
/// or `None` if the type is variable-length or unknown.
fn fixed_size_for_type(type_: &str) -> Option<usize> {
    match type_ {
        "uint8"            => Some(1),
        "uint32"           => Some(4),
        "uint64"           => Some(8),
        "secp256k1_sig"    => Some(65),
        "secp256k1_pubkey" => Some(33),
        "schnorr_sig"      => Some(64),
        "bytes"            => None,  // variable-length, length-prefixed
        _                  => None,
    }
}

/// Returns `true` for types that are known to this decoder.
fn is_known_type(type_: &str) -> bool {
    matches!(
        type_,
        "uint8" | "uint32" | "uint64"
        | "secp256k1_sig" | "secp256k1_pubkey" | "schnorr_sig"
        | "bytes"
    )
}

pub struct IdlClient {
    pub http: reqwest::Client,
    pub cache: HashMap<[u8; 32], IdlDocument>,
}

impl IdlClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            cache: HashMap::new(),
        }
    }

    pub async fn fetch(&self, indexer_url: &str, code_hash: [u8; 32]) -> Result<IdlDocument> {
        if let Some(doc) = self.cache.get(&code_hash) {
            return Ok(doc.clone());
        }
        let url = format!("{}/idl/{}", indexer_url, hex::encode(code_hash));
        let res = self.http.get(&url).send().await?;

        if !res.status().is_success() {
            return Err(crate::IdlError::HttpError {
                status: res.status().as_u16(),
            });
        }

        let doc = res.json::<IdlDocument>().await?;
        Ok(doc)
    }

    pub fn verify(
        &mut self,
        code_hash: [u8; 32],
        idl_json_bytes: &[u8],
        code_cell_data: &[u8],
    ) -> Result<()> {
        if code_cell_data.len() < 32 {
            return Err(crate::IdlError::InsufficientData {
                actual: code_cell_data.len(),
            });
        }
        let idl_hash = &code_cell_data[code_cell_data.len() - 32..];

        let idl_json_bytes_hash = sha256(idl_json_bytes);

        if idl_json_bytes_hash.as_slice() != idl_hash {
            return Err(crate::IdlError::HashMismatch {
                computed: hex::encode(idl_json_bytes_hash),
                expected: hex::encode(idl_hash),
            });
        }

        let doc: IdlDocument = serde_json::from_slice(idl_json_bytes)?;
        self.cache.insert(code_hash, doc);
        Ok(())
    }

    pub async fn witness_requirements(
        &self,
        indexer_url: &str,
        code_hash: [u8; 32],
    ) -> Result<Vec<WitnessField>> {
        let doc = if let Some(doc) = self.cache.get(&code_hash) {
            doc.clone()
        } else {
            self.fetch(indexer_url, code_hash).await?
        };
        Ok(doc.witness)
    }

    /// Structurally validate a raw witness buffer against an IDL field list.
    ///
    /// This is Tier-1 (structural) validation for PSCT use cases. It does NOT
    /// verify cryptographic signatures — it checks that the witness buffer:
    ///
    /// - Decodes correctly field-by-field in declaration order
    /// - Has the right byte count for every fixed-size field
    /// - Has a valid 4-byte LE length prefix for every variable-length field
    /// - Contains no trailing bytes after all fields are consumed
    ///
    /// Wire format (mirrors `ckb-idl-derive` generated `from_witness_args`):
    /// - `uint8`            → 1 byte
    /// - `uint32`           → 4 bytes, little-endian
    /// - `uint64`           → 8 bytes, little-endian
    /// - `secp256k1_sig`    → 65 bytes
    /// - `secp256k1_pubkey` → 33 bytes
    /// - `schnorr_sig`      → 64 bytes
    /// - `bytes`            → 4-byte LE length prefix, then that many bytes
    ///
    /// # Errors
    ///
    /// - [`IdlError::UnknownType`] — field uses a type not known to this decoder
    /// - [`IdlError::FieldTooShort`] — buffer exhausted before field was fully read
    /// - [`IdlError::TrailingBytes`] — extra bytes remain after all fields decoded
    ///
    /// # Returns
    ///
    /// A `Vec<ValidatedField>` in the same order as the IDL `fields` slice,
    /// with the decoded value for each field.
    pub fn validate_witness_bytes(
        &self,
        fields: &[WitnessField],
        raw_witness: &[u8],
    ) -> Result<Vec<ValidatedField>> {
        let mut cursor = 0usize;
        let mut validated = Vec::with_capacity(fields.len());

        for field in fields {
            // Reject unknown types immediately so callers get a clear error.
            if !is_known_type(&field.type_) {
                return Err(IdlError::UnknownType {
                    field: field.name.clone(),
                    type_: field.type_.clone(),
                });
            }

            let decoded = match field.type_.as_str() {
                // ── 1-byte scalar ────────────────────────────────────────────
                "uint8" => {
                    let need = 1;
                    let have = raw_witness.len().saturating_sub(cursor);
                    if have < need {
                        return Err(IdlError::FieldTooShort {
                            field: field.name.clone(),
                            expected: need,
                            got: have,
                        });
                    }
                    let v = raw_witness[cursor];
                    cursor += need;
                    DecodedValue::U8(v)
                }

                // ── 4-byte scalar ────────────────────────────────────────────
                "uint32" => {
                    let need = 4;
                    let have = raw_witness.len().saturating_sub(cursor);
                    if have < need {
                        return Err(IdlError::FieldTooShort {
                            field: field.name.clone(),
                            expected: need,
                            got: have,
                        });
                    }
                    let v = u32::from_le_bytes(
                        raw_witness[cursor..cursor + need].try_into().unwrap(),
                    );
                    cursor += need;
                    DecodedValue::U32(v)
                }

                // ── 8-byte scalar ────────────────────────────────────────────
                "uint64" => {
                    let need = 8;
                    let have = raw_witness.len().saturating_sub(cursor);
                    if have < need {
                        return Err(IdlError::FieldTooShort {
                            field: field.name.clone(),
                            expected: need,
                            got: have,
                        });
                    }
                    let v = u64::from_le_bytes(
                        raw_witness[cursor..cursor + need].try_into().unwrap(),
                    );
                    cursor += need;
                    DecodedValue::U64(v)
                }

                // ── Fixed byte arrays ────────────────────────────────────────
                t @ ("secp256k1_sig" | "secp256k1_pubkey" | "schnorr_sig") => {
                    let need = fixed_size_for_type(t).unwrap();
                    let have = raw_witness.len().saturating_sub(cursor);
                    if have < need {
                        return Err(IdlError::FieldTooShort {
                            field: field.name.clone(),
                            expected: need,
                            got: have,
                        });
                    }
                    let bytes = raw_witness[cursor..cursor + need].to_vec();
                    cursor += need;
                    DecodedValue::Bytes(bytes)
                }

                // ── Variable-length bytes (length-prefixed) ──────────────────
                "bytes" => {
                    // Read 4-byte LE length prefix.
                    let prefix_need = 4;
                    let prefix_have = raw_witness.len().saturating_sub(cursor);
                    if prefix_have < prefix_need {
                        return Err(IdlError::FieldTooShort {
                            field: field.name.clone(),
                            expected: prefix_need,
                            got: prefix_have,
                        });
                    }
                    let len = u32::from_le_bytes(
                        raw_witness[cursor..cursor + prefix_need].try_into().unwrap(),
                    ) as usize;
                    cursor += prefix_need;

                    // Read `len` bytes of payload.
                    let payload_have = raw_witness.len().saturating_sub(cursor);
                    if payload_have < len {
                        return Err(IdlError::FieldTooShort {
                            field: field.name.clone(),
                            expected: len,
                            got: payload_have,
                        });
                    }
                    let bytes = raw_witness[cursor..cursor + len].to_vec();
                    cursor += len;
                    DecodedValue::Bytes(bytes)
                }

                // Unreachable — guarded by is_known_type above.
                _ => unreachable!(),
            };

            validated.push(ValidatedField {
                name: field.name.clone(),
                type_: field.type_.clone(),
                required: field.required,
                value: decoded,
            });
        }

        // Any remaining bytes mean the witness is larger than the IDL describes.
        let trailing = raw_witness.len().saturating_sub(cursor);
        if trailing > 0 {
            return Err(IdlError::TrailingBytes {
                trailing,
                field_count: fields.len(),
            });
        }

        Ok(validated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DecodedValue;

    fn field(name: &str, type_: &str, required: bool) -> WitnessField {
        WitnessField {
            name: name.to_string(),
            type_: type_.to_string(),
            required,
            description: None,
        }
    }

    // ── validate_witness_bytes unit tests ────────────────────────────────────

    #[test]
    fn empty_fields_empty_buf_ok() {
        let client = IdlClient::new();
        let result = client.validate_witness_bytes(&[], &[]);
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn uint8_roundtrip() {
        let client = IdlClient::new();
        let fields = [field("difficulty", "uint8", true)];
        let buf = [42u8];
        let out = client.validate_witness_bytes(&fields, &buf).unwrap();
        assert_eq!(out[0].value, DecodedValue::U8(42));
    }

    #[test]
    fn uint32_roundtrip() {
        let client = IdlClient::new();
        let fields = [field("nonce", "uint32", true)];
        let v: u32 = 0x_DEAD_BEEF;
        let buf = v.to_le_bytes();
        let out = client.validate_witness_bytes(&fields, &buf).unwrap();
        assert_eq!(out[0].value, DecodedValue::U32(v));
    }

    #[test]
    fn uint64_roundtrip() {
        let client = IdlClient::new();
        let fields = [field("unlock_after_ms", "uint64", true)];
        let v: u64 = 1_700_000_000_000;
        let buf = v.to_le_bytes();
        let out = client.validate_witness_bytes(&fields, &buf).unwrap();
        assert_eq!(out[0].value, DecodedValue::U64(v));
    }

    #[test]
    fn secp256k1_sig_roundtrip() {
        let client = IdlClient::new();
        let fields = [field("signature", "secp256k1_sig", true)];
        let mut buf = [0u8; 65];
        buf[0] = 0x04;
        buf[64] = 0x01;
        let out = client.validate_witness_bytes(&fields, &buf).unwrap();
        assert_eq!(out[0].value, DecodedValue::Bytes(buf.to_vec()));
    }

    #[test]
    fn bytes_roundtrip() {
        let client = IdlClient::new();
        let fields = [field("preimage", "bytes", true)];
        let payload = b"hello_ckb";
        let len = payload.len() as u32;
        let mut buf = len.to_le_bytes().to_vec();
        buf.extend_from_slice(payload);
        let out = client.validate_witness_bytes(&fields, &buf).unwrap();
        assert_eq!(out[0].value, DecodedValue::Bytes(payload.to_vec()));
    }

    #[test]
    fn multi_field_decode() {
        // Mirrors the timelock-lock Witness: [u8; 65] + u64 + Vec<u8>
        let client = IdlClient::new();
        let fields = [
            field("signature", "secp256k1_sig", true),
            field("unlock_after_ms", "uint64", true),
            field("extra", "bytes", false),
        ];

        let sig = [0x01u8; 65];
        let ts: u64 = 1_750_000_000_000u64;
        let payload = b"merkle_proof";

        let mut buf = vec![];
        buf.extend_from_slice(&sig);
        buf.extend_from_slice(&ts.to_le_bytes());
        let plen = payload.len() as u32;
        buf.extend_from_slice(&plen.to_le_bytes());
        buf.extend_from_slice(payload);

        let out = client.validate_witness_bytes(&fields, &buf).unwrap();

        assert_eq!(out[0].value, DecodedValue::Bytes(sig.to_vec()));
        assert_eq!(out[1].value, DecodedValue::U64(ts));
        assert_eq!(out[2].value, DecodedValue::Bytes(payload.to_vec()));
    }

    #[test]
    fn field_too_short_returns_error() {
        let client = IdlClient::new();
        let fields = [field("sig", "secp256k1_sig", true)];
        let short = [0u8; 10]; // need 65
        let err = client.validate_witness_bytes(&fields, &short).unwrap_err();
        assert!(matches!(err, IdlError::FieldTooShort { expected: 65, got: 10, .. }));
    }

    #[test]
    fn trailing_bytes_returns_error() {
        let client = IdlClient::new();
        let fields = [field("val", "uint8", true)];
        let buf = [1u8, 2u8, 3u8]; // 1 byte for uint8, 2 trailing
        let err = client.validate_witness_bytes(&fields, &buf).unwrap_err();
        assert!(matches!(err, IdlError::TrailingBytes { trailing: 2, .. }));
    }

    #[test]
    fn unknown_type_returns_error() {
        let client = IdlClient::new();
        let fields = [field("mystery", "molecule_bytes", true)];
        let buf = [0u8; 32];
        let err = client.validate_witness_bytes(&fields, &buf).unwrap_err();
        assert!(matches!(err, IdlError::UnknownType { .. }));
    }

    // ── verify unit test (existing) ──────────────────────────────────────────

    #[test]
    fn test_verify_minimal() {
        let doc_json = r#"{"idl_version":"","name":"","witness":[]}"#;
        let idl_json_bytes = doc_json.as_bytes();
        let hash = sha256(idl_json_bytes);
        let mut code_cell_data: Vec<u8> = vec![];
        code_cell_data.extend_from_slice(&hash);

        let mut client = IdlClient::new();
        let result = client.verify([0u8; 32], idl_json_bytes, &code_cell_data);
        assert!(result.is_ok(), "verify failed: {:?}", result);
    }

    // ── test vectors ─────────────────────────────────────────────────────────

    /// Runs every case in `test-vectors.json` through `validate_witness_bytes`.
    ///
    /// This is the canonical correctness check for the wire format decoder.
    /// Any reimplementation of the ckb-idl wire format must produce identical
    /// results for every vector in that file.
    #[test]
    fn test_vectors_file() {
        let vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors.json");
        let json = std::fs::read_to_string(vectors_path)
            .expect("test-vectors.json not found at crate root");

        let root: serde_json::Value =
            serde_json::from_str(&json).expect("test-vectors.json is not valid JSON");

        let vectors = root["vectors"]
            .as_array()
            .expect("test-vectors.json must have a 'vectors' array");

        let client = IdlClient::new();

        for vec in vectors {
            let id = vec["id"].as_str().unwrap_or("<unnamed>");
            let description = vec["description"].as_str().unwrap_or("");
            let expect = vec["expect"].as_str().expect("missing 'expect'");

            // Parse field list
            let fields: Vec<WitnessField> =
                serde_json::from_value(vec["fields"].clone())
                    .unwrap_or_else(|e| panic!("[{id}] failed to parse fields: {e}"));

            // Decode wire hex (spaces are allowed as separators)
            let wire_hex: String = vec["wire_hex"]
                .as_str()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let wire = hex::decode(&wire_hex)
                .unwrap_or_else(|e| panic!("[{id}] invalid wire_hex: {e}"));

            match expect {
                "valid" => {
                    let result = client.validate_witness_bytes(&fields, &wire);
                    assert!(
                        result.is_ok(),
                        "[{id}] {description}\n  expected valid, got error: {:?}",
                        result.unwrap_err()
                    );

                    // If the vector includes decoded expectations, verify them
                    if let Some(expected_decoded) = vec["decoded"].as_array() {
                        let got = result.unwrap();
                        assert_eq!(
                            got.len(),
                            expected_decoded.len(),
                            "[{id}] decoded field count mismatch"
                        );
                        for (i, expected_field) in expected_decoded.iter().enumerate() {
                            let got_field = &got[i];
                            let exp_name = expected_field["name"].as_str().unwrap();
                            assert_eq!(
                                got_field.name, exp_name,
                                "[{id}] field[{i}] name mismatch"
                            );

                            // Check value if provided
                            if let Some(hex_val) = expected_field["value_hex"].as_str() {
                                let expected_bytes = hex::decode(hex_val)
                                    .unwrap_or_else(|e| panic!("[{id}] bad value_hex: {e}"));
                                assert_eq!(
                                    got_field.value,
                                    DecodedValue::Bytes(expected_bytes),
                                    "[{id}] field[{i}] ({exp_name}) value mismatch"
                                );
                            } else if let Some(u_val) = expected_field["value_u64"].as_u64() {
                                let expected_val = match got_field.type_.as_str() {
                                    "uint8"  => DecodedValue::U8(u_val as u8),
                                    "uint32" => DecodedValue::U32(u_val as u32),
                                    "uint64" => DecodedValue::U64(u_val),
                                    other => panic!("[{id}] unexpected numeric type {other}"),
                                };
                                assert_eq!(
                                    got_field.value, expected_val,
                                    "[{id}] field[{i}] ({exp_name}) value mismatch"
                                );
                            }
                        }
                    }
                }
                "error" => {
                    let result = client.validate_witness_bytes(&fields, &wire);
                    assert!(
                        result.is_err(),
                        "[{id}] {description}\n  expected error, but got Ok"
                    );

                    // Optionally verify the error kind matches
                    let expected_error = vec["error"].as_str().unwrap_or("");
                    let err_str = format!("{:?}", result.unwrap_err());
                    assert!(
                        err_str.contains(expected_error),
                        "[{id}] expected error kind '{expected_error}', got: {err_str}"
                    );
                }
                other => panic!("[{id}] unknown 'expect' value: {other}"),
            }
        }

        println!("All {} test vectors passed.", vectors.len());
    }
}
