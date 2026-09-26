mod common;

use ckb_idl_client::{IdlClient, IdlError, WitnessField};
use proptest::prelude::*;

/// Encode a slice of (type, payload_bytes) pairs into a wire buffer using
/// the same length-prefix format as ckb-idl-derive's from_witness_args.
fn encode_wire(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (type_, bytes) in fields {
        match *type_ {
            "uint8" => buf.extend_from_slice(bytes),
            "uint32" => buf.extend_from_slice(bytes),
            "uint64" => buf.extend_from_slice(bytes),
            "secp256k1_sig" | "secp256k1_pubkey" | "schnorr_sig" => buf.extend_from_slice(bytes),
            "bytes" => {
                let len = bytes.len() as u32;
                buf.extend_from_slice(&len.to_le_bytes());
                buf.extend_from_slice(bytes);
            }
            _ => {}
        }
    }
    buf
}

fn known_types() -> Vec<(&'static str, usize)> {
    vec![
        ("uint8", 1),
        ("uint32", 4),
        ("uint64", 8),
        ("secp256k1_sig", 65),
        ("secp256k1_pubkey", 33),
        ("schnorr_sig", 64),
    ]
}

/// Strategy: pick a random known fixed-size type and generate the right number of bytes.
fn arb_fixed_field() -> impl Strategy<Value = (&'static str, Vec<u8>)> {
    let types = known_types();
    (0..types.len()).prop_flat_map(move |i| {
        let (type_, size) = types[i];
        proptest::collection::vec(any::<u8>(), size..=size).prop_map(move |bytes| (type_, bytes))
    })
}

/// Strategy: generate a `bytes` field with a random payload 0–128 bytes.
fn arb_bytes_field() -> impl Strategy<Value = (&'static str, Vec<u8>)> {
    proptest::collection::vec(any::<u8>(), 0..128).prop_map(|bytes| ("bytes", bytes))
}

/// Strategy: either a fixed or variable field.
fn arb_any_field() -> impl Strategy<Value = (&'static str, Vec<u8>)> {
    prop_oneof![arb_fixed_field(), arb_bytes_field()]
}

// Property: validate_witness_bytes succeeds on correctly encoded buffers.
// For any sequence of known-type fields encoded with the standard wire format,
// decode must succeed and return one ValidatedField per input field.
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(128))]
    #[test]
    fn prop_valid_wire_always_decodes(
        raw_fields in proptest::collection::vec(arb_any_field(), 0..=8),
    ) {
        let wire = encode_wire(&raw_fields);

        let idl_fields: Vec<WitnessField> = raw_fields.iter().enumerate().map(|(i, (t, _))| {
            WitnessField {
                name: format!("field_{i}"),
                type_: t.to_string(),
                required: true,
                description: None,
                items: None,
                fields: None,
                variants: None,
                wire_type: None,
            }
        }).collect();

        let client = IdlClient::new();
        let result = client.validate_witness_bytes(&idl_fields, &wire);
        prop_assert!(result.is_ok(), "decode failed: {:?}", result);
        prop_assert_eq!(result.unwrap().len(), idl_fields.len());
    }
}

// Property: decoded byte values round-trip through the wire format exactly.
// The bytes decoded for each field must equal the bytes that were encoded.
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(128))]
    #[test]
    fn prop_decoded_bytes_match_encoded(
        raw_fields in proptest::collection::vec(arb_any_field(), 1..=6),
    ) {
        let wire = encode_wire(&raw_fields);

        let idl_fields: Vec<WitnessField> = raw_fields.iter().enumerate().map(|(i, (t, _))| {
            WitnessField {
                name: format!("f{i}"),
                type_: t.to_string(),
                required: true,
                description: None,
                items: None,
                fields: None,
                variants: None,
                wire_type: None,
            }
        }).collect();

        let client = IdlClient::new();
        let validated = client.validate_witness_bytes(&idl_fields, &wire).unwrap();

        for (i, (validated_field, (_, expected_bytes))) in
            validated.iter().zip(raw_fields.iter()).enumerate()
        {
            use ckb_idl_client::DecodedValue;
            match &validated_field.value {
                DecodedValue::Bytes(got) => {
                    prop_assert_eq!(got, expected_bytes, "field {} bytes mismatch", i);
                }
                DecodedValue::U8(v) => {
                    prop_assert_eq!(*v, expected_bytes[0], "field {} u8 mismatch", i);
                }
                DecodedValue::U32(v) => {
                    let expected = u32::from_le_bytes(expected_bytes[..4].try_into().unwrap());
                    prop_assert_eq!(*v, expected, "field {} u32 mismatch", i);
                }
                DecodedValue::U64(v) => {
                    let expected = u64::from_le_bytes(expected_bytes[..8].try_into().unwrap());
                    prop_assert_eq!(*v, expected, "field {} u64 mismatch", i);
                }
                other => prop_assert!(false, "unexpected decoded value for field {}: {:?}", i, other),
            }
        }
    }
}

// Property: truncating the wire buffer by any amount causes FieldTooShort.
// For a non-empty valid wire buffer, removing the last byte must produce
// FieldTooShort (or occasionally an empty bytes field decodes successfully
// if the truncation only removes trailing payload bytes of length 0).
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn prop_truncated_wire_fails(
        // Use 32 bytes for the test — just needs to be shorter than the field size.
        sig_prefix in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let fields = [WitnessField {
            name: "sig".to_string(),
            type_: "secp256k1_sig".to_string(),
            required: true,
            description: None,
            items: None,
                fields: None,
                variants: None,
                wire_type: None,
        }];

        // Any buffer shorter than 65 bytes must fail for a secp256k1_sig field.
        prop_assume!(sig_prefix.len() < 65);

        let client = IdlClient::new();
        let result = client.validate_witness_bytes(&fields, &sig_prefix);
        prop_assert!(
            matches!(result, Err(IdlError::FieldTooShort { .. })),
            "expected FieldTooShort for len {}, got {:?}", sig_prefix.len(), result
        );
    }
}

// Property: trailing bytes always produce TrailingBytes error.
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn prop_trailing_bytes_always_errors(
        val in any::<u8>(),
        extra in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        let fields = [WitnessField {
            name: "x".to_string(),
            type_: "uint8".to_string(),
            required: true,
            description: None,
            items: None,
            fields: None,
            variants: None,
            wire_type: None,
        }];

        let mut buf = vec![val];
        buf.extend_from_slice(&extra);

        let client = IdlClient::new();
        let result = client.validate_witness_bytes(&fields, &buf);
        prop_assert!(
            matches!(result, Err(IdlError::TrailingBytes { trailing, .. }) if trailing == extra.len()),
            "expected TrailingBytes {{ trailing: {} }}, got {:?}", extra.len(), result
        );
    }
}
