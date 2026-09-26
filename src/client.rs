use crate::{
    IdlDocument, IdlError, Result, WitnessField,
    types::{DecodedField, DecodedValue, VectorItem, WitnessObject},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const IDL_TRAILER_MAGIC: [u8; 8] = *b"CKBIDL\0\0";
const IDL_TRAILER_VERSION: u8 = 1;
const IDL_TRAILER_FLAGS: u8 = 0;
const IDL_TRAILER_PAYLOAD_LEN: usize = 34;
const IDL_TRAILER_LEN: usize = IDL_TRAILER_PAYLOAD_LEN + 4 + IDL_TRAILER_MAGIC.len();

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
        "uint8" => Some(1),
        "uint16" => Some(2),
        "uint32" => Some(4),
        "uint64" => Some(8),
        "uint128" => Some(16),
        "secp256k1_sig" => Some(65),
        "secp256k1_pubkey" => Some(33),
        "schnorr_sig" => Some(64),
        "blake2b_hash" => Some(32),
        "bytes" => None, // variable-length, length-prefixed
        _ => type_
            .strip_prefix("bytes_fixed_")
            .and_then(|size| size.parse::<usize>().ok())
            .filter(|size| *size > 0),
    }
}

pub struct IdlClient {
    pub http: reqwest::Client,
    cache: HashMap<[u8; 32], IdlDocument>,
}

impl IdlClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            cache: HashMap::new(),
        }
    }

    pub async fn fetch_bytes(&self, registry_url: &str, code_hash: [u8; 32]) -> Result<Vec<u8>> {
        let url = format!("{registry_url}/idl/{}", hex::encode(code_hash));
        let response = self.http.get(url).send().await?;

        if !response.status().is_success() {
            return Err(IdlError::HttpError {
                status: response.status().as_u16(),
            });
        }

        Ok(response.bytes().await?.to_vec())
    }

    pub async fn fetch_verify_and_cache(
        &mut self,
        registry_url: &str,
        code_hash: [u8; 32],
        code_cell_data: &[u8],
    ) -> Result<&IdlDocument> {
        let idl_bytes = self.fetch_bytes(registry_url, code_hash).await?;
        self.verify_and_cache(code_hash, &idl_bytes, code_cell_data)
    }

    pub fn verify_and_cache(
        &mut self,
        code_hash: [u8; 32],
        idl_bytes: &[u8],
        code_cell_data: &[u8],
    ) -> Result<&IdlDocument> {
        Self::verify_commitment(idl_bytes, code_cell_data)?;
        let document: IdlDocument = serde_json::from_slice(idl_bytes)?;
        document.validate()?;

        self.cache.insert(code_hash, document);

        Ok(self.cache.get(&code_hash).expect("just inserted"))
    }

    pub fn verify_commitment(idl_bytes: &[u8], code_cell_data: &[u8]) -> Result<()> {
        if code_cell_data.len() < IDL_TRAILER_LEN {
            return Err(IdlError::InsufficientData {
                actual: code_cell_data.len(),
            });
        }

        let total = code_cell_data.len();
        let magic_offset = total - IDL_TRAILER_MAGIC.len();
        if code_cell_data[magic_offset..] != IDL_TRAILER_MAGIC {
            return Err(IdlError::InvalidTrailer {
                reason: "magic bytes do not match Binding Trailer 1",
            });
        }

        let length_offset = magic_offset - 4;
        let payload_len = u32::from_le_bytes(
            code_cell_data[length_offset..magic_offset]
                .try_into()
                .expect("four-byte trailer length slice"),
        ) as usize;
        if payload_len != IDL_TRAILER_PAYLOAD_LEN {
            return Err(IdlError::InvalidTrailer {
                reason: "payload length must be 34 bytes",
            });
        }

        let payload_offset =
            length_offset
                .checked_sub(payload_len)
                .ok_or(IdlError::InvalidTrailer {
                    reason: "payload length exceeds code-cell data",
                })?;
        let payload = &code_cell_data[payload_offset..length_offset];

        if payload[0] != IDL_TRAILER_VERSION {
            return Err(IdlError::InvalidTrailer {
                reason: "unsupported trailer version",
            });
        }
        if payload[1] != IDL_TRAILER_FLAGS {
            return Err(IdlError::InvalidTrailer {
                reason: "unknown trailer flags",
            });
        }

        let parsed: serde_json::Value = serde_json::from_slice(idl_bytes)?;
        let canonical = serde_json_canonicalizer::to_vec(&parsed)
            .expect("serde_json::Value is canonicalisable");
        if canonical.as_slice() != idl_bytes {
            return Err(IdlError::NonCanonicalDocument);
        }

        let computed = sha256(idl_bytes);
        let expected = &payload[2..34];
        if computed.as_slice() != expected {
            return Err(IdlError::HashMismatch {
                computed: hex::encode(computed),
                expected: hex::encode(expected),
            });
        }

        Ok(())
    }

    pub fn verify(
        &mut self,
        code_hash: [u8; 32],
        idl_json_bytes: &[u8],
        code_cell_data: &[u8],
    ) -> Result<()> {
        self.verify_and_cache(code_hash, idl_json_bytes, code_cell_data)?;
        Ok(())
    }

    pub fn lock_witness_requirements(
        &self,
        // indexer_url: &str,
        code_hash: [u8; 32],
    ) -> Result<&[WitnessField]> {
        let doc = self
            .cache
            .get(&code_hash)
            .ok_or(IdlError::DocumentNotVerified {
                code_hash: hex::encode(code_hash),
            })?;
        Ok(&doc.lock_witness()?.fields)
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
    /// - `uint8`, `uint16`, `uint32`, `uint64`, `uint128` → little-endian integers
    /// - `bytes_fixed_N` → exactly `N` bytes
    /// - `bytes` → 4-byte LE length prefix, then that many bytes
    /// - `vector` → 4-byte LE count, then typed elements
    /// - `struct` → nested fields in declaration order
    /// - `union` → 4-byte LE tag, then the selected variant's fields
    ///
    /// When `wire_type` is present, it determines the structural encoding;
    /// `type` remains the wallet-facing semantic label.
    ///
    /// # Errors
    ///
    /// - [`IdlError::UnknownType`] — field uses a type not known to this decoder
    /// - [`IdlError::FieldTooShort`] — buffer exhausted before field was fully read
    /// - [`IdlError::TrailingBytes`] — extra bytes remain after all fields decoded
    ///
    /// # Returns
    ///
    /// A `WitnessObject` in the same order as the IDL `fields` slice.
    pub fn validate_witness_bytes(
        &self,
        fields: &[WitnessField],
        raw_witness: &[u8],
    ) -> Result<WitnessObject> {
        let mut cursor = 0usize;
        let validated = Self::decode_fields_at(fields, raw_witness, &mut cursor)?;

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

    fn decode_fields_at(
        fields: &[WitnessField],
        raw: &[u8],
        cursor: &mut usize,
    ) -> Result<WitnessObject> {
        let mut validated = Vec::with_capacity(fields.len());
        for field in fields {
            let value = if !field.required && *cursor == raw.len() {
                DecodedValue::Optional(None)
            } else {
                let value = Self::decode_value(field, raw, cursor)?;
                if field.required {
                    value
                } else {
                    DecodedValue::Optional(Some(Box::new(value)))
                }
            };
            validated.push(DecodedField {
                name: field.name.clone(),
                value,
            });
        }
        Ok(WitnessObject::new(validated))
    }

    fn decode_value(field: &WitnessField, raw: &[u8], cursor: &mut usize) -> Result<DecodedValue> {
        match field.structural_type() {
            "uint8" => Ok(DecodedValue::U8(
                Self::take(raw, cursor, 1, &field.name)?[0],
            )),
            "uint16" => Ok(DecodedValue::U16(u16::from_le_bytes(
                Self::take(raw, cursor, 2, &field.name)?.try_into().unwrap(),
            ))),
            "uint32" => Ok(DecodedValue::U32(Self::read_u32(raw, cursor, &field.name)?)),
            "uint64" => Ok(DecodedValue::U64(u64::from_le_bytes(
                Self::take(raw, cursor, 8, &field.name)?.try_into().unwrap(),
            ))),
            "uint128" => Ok(DecodedValue::U128(u128::from_le_bytes(
                Self::take(raw, cursor, 16, &field.name)?
                    .try_into()
                    .unwrap(),
            ))),
            "bytes" => {
                let len = Self::read_u32(raw, cursor, &field.name)? as usize;
                Ok(DecodedValue::Bytes(
                    Self::take(raw, cursor, len, &field.name)?.to_vec(),
                ))
            }
            "vector" => Self::decode_vector(field, raw, cursor),
            "struct" => Ok(DecodedValue::Struct(Self::decode_fields_at(
                Self::nonempty_struct_fields(field)?,
                raw,
                cursor,
            )?)),
            "union" => Self::decode_union(field, raw, cursor),
            type_ => {
                if let Some(size) = fixed_size_for_type(type_) {
                    return Ok(DecodedValue::Bytes(
                        Self::take(raw, cursor, size, &field.name)?.to_vec(),
                    ));
                }
                Err(IdlError::UnknownType {
                    field: field.name.clone(),
                    type_: type_.to_string(),
                })
            }
        }
    }

    fn decode_vector(field: &WitnessField, raw: &[u8], cursor: &mut usize) -> Result<DecodedValue> {
        let item = field
            .items
            .as_deref()
            .ok_or_else(|| IdlError::InvalidFieldSchema {
                field: field.name.clone(),
                reason: "vector is missing items",
            })?;
        let count = Self::read_u32(raw, cursor, &field.name)? as usize;
        if count == 0 {
            return Err(IdlError::EmptyVector {
                field: field.name.clone(),
            });
        }

        let item_size = Self::vector_item_size(item, &field.name)?;
        let encoded_size =
            count
                .checked_mul(item_size)
                .ok_or_else(|| IdlError::LengthOverflow {
                    field: field.name.clone(),
                })?;
        let remaining = raw.len().saturating_sub(*cursor);
        if remaining < encoded_size {
            return Err(IdlError::FieldTooShort {
                field: field.name.clone(),
                expected: encoded_size,
                got: remaining,
            });
        }

        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| IdlError::LengthOverflow {
                field: field.name.clone(),
            })?;
        for _ in 0..count {
            values.push(Self::decode_vector_item(item, &field.name, raw, cursor)?);
        }
        Ok(DecodedValue::Vector(values))
    }

    fn vector_item_size(item: &VectorItem, field_name: &str) -> Result<usize> {
        match item.structural_type() {
            "uint16" => Ok(2),
            "uint32" => Ok(4),
            "uint64" => Ok(8),
            "uint128" => Ok(16),
            type_ if type_.starts_with("bytes_fixed_") => {
                fixed_size_for_type(type_).ok_or_else(|| IdlError::UnknownType {
                    field: field_name.to_string(),
                    type_: type_.to_string(),
                })
            }
            type_ => Err(IdlError::UnknownType {
                field: field_name.to_string(),
                type_: type_.to_string(),
            }),
        }
    }

    fn decode_vector_item(
        item: &VectorItem,
        field_name: &str,
        raw: &[u8],
        cursor: &mut usize,
    ) -> Result<DecodedValue> {
        match item.structural_type() {
            "uint16" => Ok(DecodedValue::U16(u16::from_le_bytes(
                Self::take(raw, cursor, 2, field_name)?.try_into().unwrap(),
            ))),
            "uint32" => Ok(DecodedValue::U32(Self::read_u32(raw, cursor, field_name)?)),
            "uint64" => Ok(DecodedValue::U64(u64::from_le_bytes(
                Self::take(raw, cursor, 8, field_name)?.try_into().unwrap(),
            ))),
            "uint128" => Ok(DecodedValue::U128(u128::from_le_bytes(
                Self::take(raw, cursor, 16, field_name)?.try_into().unwrap(),
            ))),
            type_ if type_.starts_with("bytes_fixed_") => {
                let size = fixed_size_for_type(type_).ok_or_else(|| IdlError::UnknownType {
                    field: field_name.to_string(),
                    type_: type_.to_string(),
                })?;
                Ok(DecodedValue::Bytes(
                    Self::take(raw, cursor, size, field_name)?.to_vec(),
                ))
            }
            type_ => Err(IdlError::UnknownType {
                field: field_name.to_string(),
                type_: type_.to_string(),
            }),
        }
    }

    fn decode_union(field: &WitnessField, raw: &[u8], cursor: &mut usize) -> Result<DecodedValue> {
        let variants = field
            .variants
            .as_deref()
            .filter(|variants| !variants.is_empty())
            .ok_or_else(|| IdlError::InvalidFieldSchema {
                field: field.name.clone(),
                reason: "union variants must not be empty",
            })?;
        let tag = Self::read_u32(raw, cursor, &field.name)?;
        let variant = variants
            .iter()
            .find(|variant| variant.tag == tag)
            .ok_or_else(|| IdlError::UnknownUnionTag {
                field: field.name.clone(),
                tag,
            })?;
        if variant.fields.is_empty() {
            return Err(IdlError::InvalidFieldSchema {
                field: field.name.clone(),
                reason: "union variant fields must not be empty",
            });
        }
        Ok(DecodedValue::Union {
            tag,
            variant: variant.name.clone(),
            value: Self::decode_fields_at(&variant.fields, raw, cursor)?,
        })
    }

    fn nonempty_struct_fields(field: &WitnessField) -> Result<&[WitnessField]> {
        field
            .fields
            .as_deref()
            .filter(|fields| !fields.is_empty())
            .ok_or_else(|| IdlError::InvalidFieldSchema {
                field: field.name.clone(),
                reason: "struct fields must not be empty",
            })
    }

    fn read_u32(raw: &[u8], cursor: &mut usize, field: &str) -> Result<u32> {
        Ok(u32::from_le_bytes(
            Self::take(raw, cursor, 4, field)?.try_into().unwrap(),
        ))
    }

    fn take<'a>(raw: &'a [u8], cursor: &mut usize, count: usize, field: &str) -> Result<&'a [u8]> {
        let end = cursor
            .checked_add(count)
            .ok_or_else(|| IdlError::LengthOverflow {
                field: field.to_string(),
            })?;
        if end > raw.len() {
            return Err(IdlError::FieldTooShort {
                field: field.to_string(),
                expected: count,
                got: raw.len().saturating_sub(*cursor),
            });
        }
        let bytes = &raw[*cursor..end];
        *cursor = end;
        Ok(bytes)
    }

    pub fn validate_lock_witness(
        &self,
        idl: IdlDocument,
        raw_witness: &[u8],
    ) -> Result<WitnessObject> {
        self.decode_lock_witness(&idl, raw_witness)
    }

    pub fn decode_lock_witness(
        &self,
        idl: &IdlDocument,
        raw_witness: &[u8],
    ) -> Result<WitnessObject> {
        let interface = idl.validate()?;
        self.validate_witness_bytes(&interface.fields, raw_witness)
    }

    pub fn encode_lock_witness(
        &self,
        idl: &IdlDocument,
        object: &WitnessObject,
    ) -> Result<Vec<u8>> {
        let interface = idl.validate()?;
        let mut encoded = Vec::new();
        Self::encode_fields(&interface.fields, object, "", &mut encoded)?;
        Ok(encoded)
    }

    fn encode_fields(
        fields: &[WitnessField],
        object: &WitnessObject,
        parent_path: &str,
        encoded: &mut Vec<u8>,
    ) -> Result<()> {
        if object.fields.len() != fields.len() {
            return Self::invalid_object(
                parent_path,
                format!(
                    "expected {} fields, received {}",
                    fields.len(),
                    object.fields.len()
                ),
            );
        }

        let mut omitted_optional = false;
        for (field, supplied) in fields.iter().zip(&object.fields) {
            let path = Self::child_path(parent_path, &field.name);
            if supplied.name != field.name {
                return Self::invalid_object(
                    &path,
                    format!(
                        "expected field `{}`, received `{}`",
                        field.name, supplied.name
                    ),
                );
            }

            if field.required {
                if matches!(supplied.value, DecodedValue::Optional(_)) {
                    return Self::invalid_object(&path, "required field cannot be optional");
                }
                Self::encode_value(field, &supplied.value, &path, encoded)?;
                continue;
            }

            match &supplied.value {
                DecodedValue::Optional(None) => omitted_optional = true,
                DecodedValue::Optional(Some(value)) if !omitted_optional => {
                    Self::encode_value(field, value, &path, encoded)?;
                }
                DecodedValue::Optional(Some(_)) => {
                    return Self::invalid_object(
                        &path,
                        "present optional field cannot follow an absent optional field",
                    );
                }
                _ => {
                    return Self::invalid_object(
                        &path,
                        "optional field must use DecodedValue::Optional",
                    );
                }
            }
        }

        Ok(())
    }

    fn encode_value(
        field: &WitnessField,
        value: &DecodedValue,
        path: &str,
        encoded: &mut Vec<u8>,
    ) -> Result<()> {
        match (field.structural_type(), value) {
            ("uint8", DecodedValue::U8(value)) => encoded.push(*value),
            ("uint16", DecodedValue::U16(value)) => encoded.extend_from_slice(&value.to_le_bytes()),
            ("uint32", DecodedValue::U32(value)) => encoded.extend_from_slice(&value.to_le_bytes()),
            ("uint64", DecodedValue::U64(value)) => encoded.extend_from_slice(&value.to_le_bytes()),
            ("uint128", DecodedValue::U128(value)) => {
                encoded.extend_from_slice(&value.to_le_bytes())
            }
            ("bytes", DecodedValue::Bytes(bytes)) => {
                let length = u32::try_from(bytes.len()).map_err(|_| IdlError::InvalidObject {
                    path: path.to_string(),
                    reason: "byte string length exceeds u32".to_string(),
                })?;
                encoded.extend_from_slice(&length.to_le_bytes());
                encoded.extend_from_slice(bytes);
            }
            ("vector", DecodedValue::Vector(values)) => {
                Self::encode_vector(field, values, path, encoded)?;
            }
            ("struct", DecodedValue::Struct(object)) => {
                let fields = Self::nonempty_struct_fields(field)?;
                Self::encode_fields(fields, object, path, encoded)?;
            }
            (
                "union",
                DecodedValue::Union {
                    tag,
                    variant,
                    value,
                },
            ) => Self::encode_union(field, *tag, variant, value, path, encoded)?,
            (type_, DecodedValue::Bytes(bytes)) if type_.starts_with("bytes_fixed_") => {
                let expected = fixed_size_for_type(type_).unwrap();
                if bytes.len() != expected {
                    return Self::invalid_object(
                        path,
                        format!("expected {expected} bytes, received {}", bytes.len()),
                    );
                }
                encoded.extend_from_slice(bytes);
            }
            (type_, value) => {
                return Self::invalid_object(
                    path,
                    format!(
                        "expected value for structural type `{type_}`, received {}",
                        Self::value_kind(value)
                    ),
                );
            }
        }
        Ok(())
    }

    fn encode_vector(
        field: &WitnessField,
        values: &[DecodedValue],
        path: &str,
        encoded: &mut Vec<u8>,
    ) -> Result<()> {
        if values.is_empty() {
            return Self::invalid_object(path, "vectors must not be empty");
        }
        let count = u32::try_from(values.len()).map_err(|_| IdlError::InvalidObject {
            path: path.to_string(),
            reason: "vector element count exceeds u32".to_string(),
        })?;
        let item = field
            .items
            .as_deref()
            .ok_or_else(|| IdlError::InvalidObject {
                path: path.to_string(),
                reason: "vector schema is missing items".to_string(),
            })?;
        encoded.extend_from_slice(&count.to_le_bytes());
        for (index, value) in values.iter().enumerate() {
            Self::encode_vector_item(item, value, &format!("{path}/{index}"), encoded)?;
        }
        Ok(())
    }

    fn encode_vector_item(
        item: &VectorItem,
        value: &DecodedValue,
        path: &str,
        encoded: &mut Vec<u8>,
    ) -> Result<()> {
        match (item.structural_type(), value) {
            ("uint16", DecodedValue::U16(value)) => encoded.extend_from_slice(&value.to_le_bytes()),
            ("uint32", DecodedValue::U32(value)) => encoded.extend_from_slice(&value.to_le_bytes()),
            ("uint64", DecodedValue::U64(value)) => encoded.extend_from_slice(&value.to_le_bytes()),
            ("uint128", DecodedValue::U128(value)) => {
                encoded.extend_from_slice(&value.to_le_bytes())
            }
            (type_, DecodedValue::Bytes(bytes)) if fixed_size_for_type(type_).is_some() => {
                let expected = fixed_size_for_type(type_).unwrap();
                if bytes.len() != expected {
                    return Self::invalid_object(
                        path,
                        format!("expected {expected} bytes, received {}", bytes.len()),
                    );
                }
                encoded.extend_from_slice(bytes);
            }
            (type_, value) => {
                return Self::invalid_object(
                    path,
                    format!(
                        "expected vector item `{type_}`, received {}",
                        Self::value_kind(value)
                    ),
                );
            }
        }
        Ok(())
    }

    fn encode_union(
        field: &WitnessField,
        tag: u32,
        variant_name: &str,
        value: &WitnessObject,
        path: &str,
        encoded: &mut Vec<u8>,
    ) -> Result<()> {
        let variant = field
            .variants
            .as_deref()
            .and_then(|variants| variants.iter().find(|variant| variant.tag == tag))
            .ok_or_else(|| IdlError::InvalidObject {
                path: path.to_string(),
                reason: format!("unknown union tag {tag}"),
            })?;
        if variant.name != variant_name {
            return Self::invalid_object(
                path,
                format!(
                    "union tag {tag} names variant `{}`, not `{variant_name}`",
                    variant.name
                ),
            );
        }
        encoded.extend_from_slice(&tag.to_le_bytes());
        Self::encode_fields(&variant.fields, value, path, encoded)
    }

    fn child_path(parent: &str, field: &str) -> String {
        if parent.is_empty() {
            format!("/{field}")
        } else {
            format!("{parent}/{field}")
        }
    }

    fn invalid_object<T>(path: &str, reason: impl Into<String>) -> Result<T> {
        Err(IdlError::InvalidObject {
            path: path.to_string(),
            reason: reason.into(),
        })
    }

    fn value_kind(value: &DecodedValue) -> &'static str {
        match value {
            DecodedValue::Bytes(_) => "bytes",
            DecodedValue::U8(_) => "uint8",
            DecodedValue::U16(_) => "uint16",
            DecodedValue::U32(_) => "uint32",
            DecodedValue::U64(_) => "uint64",
            DecodedValue::U128(_) => "uint128",
            DecodedValue::Vector(_) => "vector",
            DecodedValue::Struct(_) => "struct",
            DecodedValue::Union { .. } => "union",
            DecodedValue::Optional(_) => "optional",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EncodingProfile, IdlInterface, InterfaceKind, UnionVariant};

    fn field(name: &str, type_: &str, required: bool) -> WitnessField {
        WitnessField {
            name: name.to_string(),
            type_: type_.to_string(),
            required,
            description: None,
            fields: None,
            variants: None,
            wire_type: None,
            items: None,
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

    fn object(fields: Vec<(&str, DecodedValue)>) -> WitnessObject {
        WitnessObject::new(
            fields
                .into_iter()
                .map(|(name, value)| DecodedField {
                    name: name.to_string(),
                    value,
                })
                .collect(),
        )
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
        assert_eq!(
            out[2].value,
            DecodedValue::Optional(Some(Box::new(DecodedValue::Bytes(payload.to_vec()))))
        );
    }

    #[test]
    fn field_too_short_returns_error() {
        let client = IdlClient::new();
        let fields = [field("sig", "secp256k1_sig", true)];
        let short = [0u8; 10]; // need 65
        let err = client.validate_witness_bytes(&fields, &short).unwrap_err();
        assert!(matches!(
            err,
            IdlError::FieldTooShort {
                expected: 65,
                got: 10,
                ..
            }
        ));
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

    #[test]
    fn semantic_override_uses_structural_size() {
        let client = IdlClient::new();
        let mut digest = field("digest", "example:digest", true);
        digest.wire_type = Some("bytes_fixed_3".to_string());

        let out = client
            .validate_witness_bytes(&[digest], &[0x11, 0x22, 0x33])
            .unwrap();
        assert_eq!(out[0].value, DecodedValue::Bytes(vec![0x11, 0x22, 0x33]));
    }

    #[test]
    fn decodes_nested_struct_vector_union_and_wide_integers() {
        let client = IdlClient::new();

        let mut values = field("values", "vector", true);
        values.items = Some(Box::new(VectorItem {
            type_: "uint32".to_string(),
            wire_type: None,
        }));

        let mut choice = field("choice", "union", true);
        choice.variants = Some(vec![crate::types::UnionVariant {
            tag: 7,
            name: "Amount".to_string(),
            fields: vec![field("amount", "uint128", true)],
        }]);

        let mut envelope = field("envelope", "struct", true);
        envelope.fields = Some(vec![field("nonce", "uint16", true), values, choice]);

        let mut wire = 9u16.to_le_bytes().to_vec();
        wire.extend_from_slice(&2u32.to_le_bytes());
        wire.extend_from_slice(&10u32.to_le_bytes());
        wire.extend_from_slice(&20u32.to_le_bytes());
        wire.extend_from_slice(&7u32.to_le_bytes());
        wire.extend_from_slice(&123u128.to_le_bytes());

        let decoded = client.validate_witness_bytes(&[envelope], &wire).unwrap();
        let DecodedValue::Struct(fields) = &decoded[0].value else {
            panic!("expected nested struct");
        };
        assert_eq!(fields[0].value, DecodedValue::U16(9));
        assert_eq!(
            fields[1].value,
            DecodedValue::Vector(vec![DecodedValue::U32(10), DecodedValue::U32(20)])
        );
        assert!(matches!(
            &fields[2].value,
            DecodedValue::Union {
                tag: 7,
                variant,
                value
            } if variant == "Amount" && value[0].value == DecodedValue::U128(123)
        ));
    }

    #[test]
    fn absent_trailing_optional_field_is_accepted() {
        let client = IdlClient::new();
        let fields = [
            field("nonce", "uint16", true),
            field("memo", "bytes", false),
        ];

        let decoded = client
            .validate_witness_bytes(&fields, &9u16.to_le_bytes())
            .unwrap();
        assert_eq!(decoded[1].value, DecodedValue::Optional(None));
    }

    // ── verify unit test (existing) ──────────────────────────────────────────

    #[test]
    fn vectors_reject_uint8_but_accept_semantic_fixed_bytes() {
        let client = IdlClient::new();

        let mut flags = field("flags", "vector", true);
        flags.items = Some(Box::new(VectorItem {
            type_: "uint8".to_string(),
            wire_type: None,
        }));
        let mut flags_wire = 2u32.to_le_bytes().to_vec();
        flags_wire.extend_from_slice(&[1, 2]);
        assert!(matches!(
            client.validate_witness_bytes(&[flags], &flags_wire),
            Err(IdlError::UnknownType { .. })
        ));

        let mut signatures = field("signatures", "vector", true);
        signatures.items = Some(Box::new(VectorItem {
            type_: "secp256k1_sig".to_string(),
            wire_type: Some("bytes_fixed_65".to_string()),
        }));

        let signature = vec![0x55; 65];
        let mut wire = 1u32.to_le_bytes().to_vec();
        wire.extend_from_slice(&signature);

        let decoded = client.validate_witness_bytes(&[signatures], &wire).unwrap();
        assert_eq!(
            decoded[0].value,
            DecodedValue::Vector(vec![DecodedValue::Bytes(signature)])
        );
    }

    #[test]
    fn witness_object_roundtrips_through_encoder() {
        let client = IdlClient::new();

        let mut values = field("values", "vector", true);
        values.items = Some(Box::new(VectorItem {
            type_: "uint32".to_string(),
            wire_type: None,
        }));

        let mut payload = field("payload", "struct", true);
        payload.fields = Some(vec![
            field("amount", "uint128", true),
            field("memo", "bytes", false),
        ]);

        let mut authorization = field("authorization", "union", true);
        authorization.variants = Some(vec![UnionVariant {
            tag: 7,
            name: "Transfer".to_string(),
            fields: vec![payload],
        }]);

        let document = document(vec![field("nonce", "uint16", true), values, authorization]);
        let object = object(vec![
            ("nonce", DecodedValue::U16(9)),
            (
                "values",
                DecodedValue::Vector(vec![DecodedValue::U32(10), DecodedValue::U32(20)]),
            ),
            (
                "authorization",
                DecodedValue::Union {
                    tag: 7,
                    variant: "Transfer".to_string(),
                    value: object(vec![(
                        "payload",
                        DecodedValue::Struct(object(vec![
                            ("amount", DecodedValue::U128(123)),
                            (
                                "memo",
                                DecodedValue::Optional(Some(Box::new(DecodedValue::Bytes(
                                    b"hello".to_vec(),
                                )))),
                            ),
                        ])),
                    )]),
                },
            ),
        ]);

        let wire = client.encode_lock_witness(&document, &object).unwrap();
        assert_eq!(
            client.decode_lock_witness(&document, &wire).unwrap(),
            object
        );
    }

    #[test]
    fn encoder_preserves_absent_trailing_optionals() {
        let client = IdlClient::new();
        let document = document(vec![
            field("nonce", "uint16", true),
            field("memo", "bytes", false),
        ]);
        let object = object(vec![
            ("nonce", DecodedValue::U16(9)),
            ("memo", DecodedValue::Optional(None)),
        ]);

        let wire = client.encode_lock_witness(&document, &object).unwrap();
        assert_eq!(wire, 9u16.to_le_bytes());
        assert_eq!(
            client.decode_lock_witness(&document, &wire).unwrap(),
            object
        );
    }

    #[test]
    fn encoder_rejects_invalid_object_shapes() {
        let client = IdlClient::new();
        let nonce_document = document(vec![field("nonce", "uint16", true)]);

        for invalid in [
            object(vec![]),
            object(vec![("other", DecodedValue::U16(9))]),
            object(vec![("nonce", DecodedValue::U32(9))]),
            object(vec![("nonce", DecodedValue::Bytes(vec![9, 0]))]),
        ] {
            assert!(matches!(
                client.encode_lock_witness(&nonce_document, &invalid),
                Err(IdlError::InvalidObject { .. })
            ));
        }

        let optionals = document(vec![
            field("first", "bytes", false),
            field("second", "bytes", false),
        ]);
        let gap = object(vec![
            ("first", DecodedValue::Optional(None)),
            (
                "second",
                DecodedValue::Optional(Some(Box::new(DecodedValue::Bytes(vec![])))),
            ),
        ]);
        assert!(matches!(
            client.encode_lock_witness(&optionals, &gap),
            Err(IdlError::InvalidObject { .. })
        ));
    }

    #[test]
    fn test_verify_minimal() {
        let doc_json = r#"{"idl_version":"0.1.0","interfaces":[{"encoding":{"id":"ckb-idl-linear-0.1.0"},"fields":[],"id":"lock_witness","kind":"witness_args.lock"}]}"#;
        let idl_json_bytes = doc_json.as_bytes();
        let code_cell_data = bind_for_test(idl_json_bytes);

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
            let fields: Vec<WitnessField> = serde_json::from_value(vec["fields"].clone())
                .unwrap_or_else(|e| panic!("[{id}] failed to parse fields: {e}"));

            // Decode wire hex (spaces are allowed as separators)
            let wire_hex: String = vec["wire_hex"]
                .as_str()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let wire =
                hex::decode(&wire_hex).unwrap_or_else(|e| panic!("[{id}] invalid wire_hex: {e}"));

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
                            assert_eq!(got_field.name, exp_name, "[{id}] field[{i}] name mismatch");

                            // Check value if provided
                            if let Some(hex_val) = expected_field["value_hex"].as_str() {
                                let expected_bytes = hex::decode(hex_val)
                                    .unwrap_or_else(|e| panic!("[{id}] bad value_hex: {e}"));
                                let expected_value = DecodedValue::Bytes(expected_bytes);
                                let expected_value = if fields[i].required {
                                    expected_value
                                } else {
                                    DecodedValue::Optional(Some(Box::new(expected_value)))
                                };
                                assert_eq!(
                                    got_field.value, expected_value,
                                    "[{id}] field[{i}] ({exp_name}) value mismatch"
                                );
                            } else if let Some(u_val) = expected_field["value_u64"].as_u64() {
                                let expected_value = match fields[i].type_.as_str() {
                                    "uint8" => DecodedValue::U8(u_val as u8),
                                    "uint32" => DecodedValue::U32(u_val as u32),
                                    "uint64" => DecodedValue::U64(u_val),
                                    other => panic!("[{id}] unexpected numeric type {other}"),
                                };
                                let expected_value = if fields[i].required {
                                    expected_value
                                } else {
                                    DecodedValue::Optional(Some(Box::new(expected_value)))
                                };
                                assert_eq!(
                                    got_field.value, expected_value,
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

    fn bind_for_test(idl: &[u8]) -> Vec<u8> {
        let mut data = b"clean-elf".to_vec();
        data.push(IDL_TRAILER_VERSION);
        data.push(IDL_TRAILER_FLAGS);
        data.extend_from_slice(&sha256(idl));
        data.extend_from_slice(&(IDL_TRAILER_PAYLOAD_LEN as u32).to_le_bytes());
        data.extend_from_slice(&IDL_TRAILER_MAGIC);
        data
    }

    #[test]
    fn verifies_binding_trailer_one() {
        let idl = br#"{"idl_version":"0.1.0","interfaces":[]}"#;
        let code = bind_for_test(idl);
        IdlClient::verify_commitment(idl, &code).unwrap();
    }

    #[test]
    fn rejects_wrong_trailer_magic() {
        let idl = br#"{"idl_version":"0.1.0","interfaces":[]}"#;
        let mut code = bind_for_test(idl);
        *code.last_mut().unwrap() = 1;
        assert!(matches!(
            IdlClient::verify_commitment(idl, &code),
            Err(IdlError::InvalidTrailer { .. })
        ));
    }

    #[test]
    fn rejects_commitment_mismatch() {
        let idl = br#"{"idl_version":"0.1.0","interfaces":[]}"#;
        let code = bind_for_test(idl);
        let other = br#"{"idl_version":"0.1.0","interfaces":[1]}"#;
        assert!(matches!(
            IdlClient::verify_commitment(other, &code),
            Err(IdlError::HashMismatch { .. })
        ));
    }

    #[test]
    fn rejects_non_canonical_idl_bytes() {
        let pretty = b"{\n  \"idl_version\": \"0.1.0\",\n  \"interfaces\": []\n}";
        let code = bind_for_test(pretty);
        assert!(matches!(
            IdlClient::verify_commitment(pretty, &code),
            Err(IdlError::NonCanonicalDocument)
        ));
    }
}
