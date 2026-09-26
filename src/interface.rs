use crate::{IdlDocument, IdlError, IdlInterface, InterfaceKind, WitnessField, types::VectorItem};

impl WitnessField {
    pub fn structural_type(&self) -> &str {
        self.wire_type.as_deref().unwrap_or(self.type_.as_str())
    }
}

impl VectorItem {
    pub fn structural_type(&self) -> &str {
        self.wire_type.as_deref().unwrap_or(self.type_.as_str())
    }
}

impl IdlDocument {
    pub fn lock_witness(&self) -> Result<&IdlInterface, IdlError> {
        if self.idl_version != "0.1.0" {
            return Err(IdlError::UnsupportedVersion {
                version: self.idl_version.clone(),
            });
        }

        let mut matches = self
            .interfaces
            .iter()
            .filter(|interface| interface.kind == InterfaceKind::WitnessArgsLock);

        let interface = matches
            .next()
            .ok_or(IdlError::MissingLockWitnessInterface)?;

        if matches.next().is_some() {
            return Err(IdlError::DuplicateLockWitnessInterface);
        }

        if interface.encoding.id != "ckb-idl-linear-0.1.0" {
            return Err(IdlError::UnsupportedEncoding {
                encoding: interface.encoding.id.clone(),
            });
        }

        Ok(interface)
    }

    pub fn validate(&self) -> Result<&IdlInterface, IdlError> {
        let interface = self.lock_witness()?;
        let interface_index = self
            .interfaces
            .iter()
            .position(|candidate| std::ptr::eq(candidate, interface))
            .expect("lock_witness returned an interface from this document");
        let interface_path = format!("/interfaces/{interface_index}");
        validate_identifier(&interface.id, &format!("{interface_path}/id"))?;
        validate_fields(&interface.fields, &format!("{interface_path}/fields"))?;
        Ok(interface)
    }
}

fn validate_fields(fields: &[WitnessField], path: &str) -> Result<(), IdlError> {
    let mut seen_optional = false;
    let mut seen_nested = false;

    for (index, field) in fields.iter().enumerate() {
        let field_path = format!("{path}/{index}");
        if seen_nested {
            return invalid(
                field_path,
                "fields cannot follow a nested struct or union under the linear encoding",
            );
        }
        if field.required {
            if seen_optional {
                return invalid(
                    format!("{field_path}/required"),
                    "required fields cannot follow optional fields",
                );
            }
        } else {
            seen_optional = true;
        }

        validate_field(field, &field_path)?;
        seen_nested = matches!(field.structural_type(), "struct" | "union");
    }

    Ok(())
}

fn validate_field(field: &WitnessField, path: &str) -> Result<(), IdlError> {
    validate_identifier(&field.name, &format!("{path}/name"))?;
    validate_declared_type(&field.type_, field.wire_type.as_deref(), path)?;

    let structural_type = field.structural_type();
    if !field.required && matches!(structural_type, "vector" | "struct" | "union") {
        return invalid(
            format!("{path}/required"),
            "optional vectors, structs, and unions are unsupported",
        );
    }

    match structural_type {
        "vector" => {
            reject_metadata(field.fields.is_some(), format!("{path}/fields"))?;
            reject_metadata(field.variants.is_some(), format!("{path}/variants"))?;
            let item = field
                .items
                .as_deref()
                .ok_or_else(|| invalid_error(format!("{path}/items"), "vector is missing items"))?;
            validate_vector_item(item, &format!("{path}/items"))?;
        }
        "struct" => {
            reject_metadata(field.items.is_some(), format!("{path}/items"))?;
            reject_metadata(field.variants.is_some(), format!("{path}/variants"))?;
            let fields = field.fields.as_deref().ok_or_else(|| {
                invalid_error(format!("{path}/fields"), "struct is missing fields")
            })?;
            if fields.is_empty() {
                return invalid(format!("{path}/fields"), "struct fields must not be empty");
            }
            validate_fields(fields, &format!("{path}/fields"))?;
        }
        "union" => {
            reject_metadata(field.items.is_some(), format!("{path}/items"))?;
            reject_metadata(field.fields.is_some(), format!("{path}/fields"))?;
            let variants = field.variants.as_deref().ok_or_else(|| {
                invalid_error(format!("{path}/variants"), "union is missing variants")
            })?;
            if variants.is_empty() {
                return invalid(
                    format!("{path}/variants"),
                    "union variants must not be empty",
                );
            }

            let mut previous_tag = None;
            for (index, variant) in variants.iter().enumerate() {
                let variant_path = format!("{path}/variants/{index}");
                validate_identifier(&variant.name, &format!("{variant_path}/name"))?;
                if previous_tag.is_some_and(|tag| variant.tag <= tag) {
                    return invalid(
                        format!("{variant_path}/tag"),
                        "union tags must be unique and sorted in ascending order",
                    );
                }
                previous_tag = Some(variant.tag);
                if variant.fields.is_empty() {
                    return invalid(
                        format!("{variant_path}/fields"),
                        "union variant fields must not be empty",
                    );
                }
                validate_fields(&variant.fields, &format!("{variant_path}/fields"))?;
            }
        }
        _ => {
            reject_metadata(field.items.is_some(), format!("{path}/items"))?;
            reject_metadata(field.fields.is_some(), format!("{path}/fields"))?;
            reject_metadata(field.variants.is_some(), format!("{path}/variants"))?;
        }
    }

    Ok(())
}

fn validate_vector_item(item: &VectorItem, path: &str) -> Result<(), IdlError> {
    validate_declared_type(&item.type_, item.wire_type.as_deref(), path)?;
    let structural_type = item.structural_type();
    if matches!(structural_type, "uint16" | "uint32" | "uint64" | "uint128")
        || fixed_bytes_size(structural_type).is_some()
    {
        return Ok(());
    }

    invalid(
        format!("{path}/type"),
        "vector items must be uint16, uint32, uint64, uint128, or bytes_fixed_N",
    )
}

fn validate_declared_type(
    type_: &str,
    wire_type: Option<&str>,
    path: &str,
) -> Result<(), IdlError> {
    let semantic = semantic_wire_type(type_);
    if !is_structural_type(type_) && semantic.is_none() && !is_custom_semantic_type(type_) {
        return invalid(format!("{path}/type"), "unsupported IDL type");
    }

    if let Some(wire_type) = wire_type
        && !is_structural_type(wire_type)
    {
        return invalid(
            format!("{path}/wire_type"),
            "unsupported structural wire type",
        );
    }

    if semantic.is_some() || is_custom_semantic_type(type_) {
        let wire_type = wire_type.ok_or_else(|| {
            invalid_error(
                format!("{path}/wire_type"),
                "semantic types require a structural wire_type",
            )
        })?;
        if let Some(expected) = semantic
            && wire_type != expected
        {
            return invalid(
                format!("{path}/wire_type"),
                format!("semantic type `{type_}` requires `{expected}`"),
            );
        }
    }

    Ok(())
}

fn is_structural_type(type_: &str) -> bool {
    matches!(
        type_,
        "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uint128"
            | "bytes"
            | "vector"
            | "struct"
            | "union"
    ) || fixed_bytes_size(type_).is_some()
}

fn fixed_bytes_size(type_: &str) -> Option<usize> {
    let size = type_.strip_prefix("bytes_fixed_")?;
    if size.starts_with('0') || !size.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    size.parse::<usize>().ok().filter(|size| *size > 0)
}

fn semantic_wire_type(type_: &str) -> Option<&'static str> {
    match type_ {
        "secp256k1_sig" => Some("bytes_fixed_65"),
        "secp256k1_pubkey" => Some("bytes_fixed_33"),
        "schnorr_sig" => Some("bytes_fixed_64"),
        "blake2b_hash" => Some("bytes_fixed_32"),
        _ => None,
    }
}

fn is_custom_semantic_type(type_: &str) -> bool {
    let Some((namespace, name)) = type_.split_once(':') else {
        return false;
    };
    let namespace_valid = namespace
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase())
        && namespace.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        });
    let mut name = name.bytes();
    let name_valid = name
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && name.all(|byte| {
            byte == b'_' || byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
        });
    namespace_valid && name_valid
}

fn validate_identifier(identifier: &str, path: &str) -> Result<(), IdlError> {
    let mut bytes = identifier.bytes();
    let valid = bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
    if valid {
        Ok(())
    } else {
        invalid(
            path.to_string(),
            "identifier must match [A-Za-z_][A-Za-z0-9_]*",
        )
    }
}

fn reject_metadata(present: bool, path: String) -> Result<(), IdlError> {
    if present {
        invalid(path, "metadata is not valid for this structural type")
    } else {
        Ok(())
    }
}

fn invalid<T>(path: String, reason: impl Into<String>) -> Result<T, IdlError> {
    Err(invalid_error(path, reason))
}

fn invalid_error(path: String, reason: impl Into<String>) -> IdlError {
    IdlError::InvalidDocument {
        path,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EncodingProfile, UnionVariant};

    fn field(name: &str, type_: &str, required: bool) -> WitnessField {
        WitnessField {
            name: name.to_string(),
            type_: type_.to_string(),
            wire_type: None,
            required,
            description: None,
            items: None,
            fields: None,
            variants: None,
        }
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

    #[test]
    fn validates_recursive_document() {
        let mut signatures = field("signatures", "vector", true);
        signatures.items = Some(Box::new(VectorItem {
            type_: "secp256k1_sig".to_string(),
            wire_type: Some("bytes_fixed_65".to_string()),
        }));

        let mut authorization = field("authorization", "union", true);
        authorization.variants = Some(vec![
            UnionVariant {
                tag: 1,
                name: "Preimage".to_string(),
                fields: vec![field("preimage", "bytes", true)],
            },
            UnionVariant {
                tag: 2,
                name: "Signatures".to_string(),
                fields: vec![signatures],
            },
        ]);

        document(vec![authorization]).validate().unwrap();
    }

    #[test]
    fn rejects_invalid_field_layouts() {
        let cases = [
            (
                document(vec![field("not-valid", "uint8", true)]),
                "/interfaces/0/fields/0/name",
            ),
            (
                document(vec![
                    field("memo", "bytes", false),
                    field("nonce", "uint8", true),
                ]),
                "/interfaces/0/fields/1/required",
            ),
            (
                {
                    let mut vector = field("values", "vector", true);
                    vector.items = Some(Box::new(VectorItem {
                        type_: "uint8".to_string(),
                        wire_type: None,
                    }));
                    document(vec![vector])
                },
                "/interfaces/0/fields/0/items/type",
            ),
            (
                {
                    let mut semantic = field("signature", "secp256k1_sig", true);
                    semantic.wire_type = Some("bytes_fixed_64".to_string());
                    document(vec![semantic])
                },
                "/interfaces/0/fields/0/wire_type",
            ),
            (
                {
                    let mut primitive = field("value", "uint8", true);
                    primitive.items = Some(Box::new(VectorItem {
                        type_: "uint16".to_string(),
                        wire_type: None,
                    }));
                    document(vec![primitive])
                },
                "/interfaces/0/fields/0/items",
            ),
            (
                {
                    let mut nested = field("inner", "struct", true);
                    nested.fields = Some(vec![field("value", "uint8", true)]);
                    document(vec![nested, field("after", "uint8", true)])
                },
                "/interfaces/0/fields/1",
            ),
        ];

        for (document, expected_path) in cases {
            assert!(matches!(
                document.validate(),
                Err(IdlError::InvalidDocument { path, .. }) if path == expected_path
            ));
        }
    }

    #[test]
    fn rejects_unsorted_or_duplicate_union_tags() {
        let mut union = field("choice", "union", true);
        union.variants = Some(vec![
            UnionVariant {
                tag: 2,
                name: "Second".to_string(),
                fields: vec![field("value", "uint8", true)],
            },
            UnionVariant {
                tag: 1,
                name: "First".to_string(),
                fields: vec![field("value", "uint8", true)],
            },
        ]);

        assert!(matches!(
            document(vec![union]).validate(),
            Err(IdlError::InvalidDocument { path, .. })
                if path == "/interfaces/0/fields/0/variants/1/tag"
        ));
    }
}
