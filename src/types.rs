//! IDL 0.1.0 document types and decoded witness values.

use serde::{Deserialize, Serialize};

/// A complete IDL 0.1.0 document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdlDocument {
    /// IDL specification version. IDL 0.1 clients require `"0.1.0"`.
    pub idl_version: String,
    /// Interfaces described by this document.
    pub interfaces: Vec<IdlInterface>,
}

/// One top-level interface in an IDL document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdlInterface {
    /// Stable interface identifier chosen by the author.
    pub id: String,
    /// Location and role of the encoded interface.
    pub kind: InterfaceKind,
    /// Encoding profile used by the interface.
    pub encoding: EncodingProfile,
    /// Ordered top-level fields.
    pub fields: Vec<WitnessField>,
}

/// Interface locations supported by IDL 0.1.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceKind {
    /// Bytes stored in `WitnessArgs.lock`.
    #[serde(rename = "witness_args.lock")]
    WitnessArgsLock,
}

/// Identifies the wire-encoding profile for an interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodingProfile {
    /// Encoding identifier, currently `ckb-idl-linear-0.1.0`.
    pub id: String,
}

/// Legacy signing metadata container.
///
/// Signing metadata is not part of the normative IDL 0.1.0 document schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigningInfo {
    /// Signature algorithm identifier.
    pub algorithm: String,
    /// Description of the signed message.
    pub message: String,
    /// Message hash algorithm identifier.
    pub hasher: String,
}

/// Schema for one ordered witness field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessField {
    /// Field name, also used in logical object paths.
    pub name: String,

    /// Structural or wallet-facing semantic type.
    #[serde(rename = "type")]
    pub type_: String,

    /// Structural type used when `type` is semantic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_type: Option<String>,

    /// Whether bytes for this field must be present.
    pub required: bool,

    /// Optional wallet-facing field description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Element schema for a typed vector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<VectorItem>>,

    /// Ordered child fields for a nested struct.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<WitnessField>>,

    /// Tagged alternatives for a union.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variants: Option<Vec<UnionVariant>>,
}

/// Schema for one element of a typed vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorItem {
    /// Structural or semantic element type.
    #[serde(rename = "type")]
    pub type_: String,

    /// Structural element type used when `type` is semantic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_type: Option<String>,
}

/// One explicitly tagged union alternative.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnionVariant {
    /// Stable wire tag encoded as little-endian `u32`.
    pub tag: u32,
    /// Human- and machine-readable variant name.
    pub name: String,
    /// Ordered payload fields for this variant.
    pub fields: Vec<WitnessField>,
}

/// The decoded value of a single witness field after structural validation.
///
/// Fixed-size fields (`u8`, `u32`, `u64`, `[u8; N]`) are always present when
/// decoding succeeds. Variable-length fields (`bytes`) are decoded from their
/// 4-byte LE length prefix.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedValue {
    /// A raw byte slice — covers all fixed-array types (secp256k1_sig,
    /// secp256k1_pubkey, schnorr_sig) and variable-length `bytes` fields.
    Bytes(Vec<u8>),
    /// A decoded `uint8`.
    U8(u8),
    /// A decoded `uint16` (little-endian).
    U16(u16),
    /// A decoded `uint32` (little-endian).
    U32(u32),
    /// A decoded `uint64` (little-endian).
    U64(u64),
    /// A decoded `uint128` (little-endian).
    U128(u128),
    /// A count-prefixed typed vector.
    Vector(Vec<DecodedValue>),
    /// A nested struct, retaining declaration order.
    Struct(WitnessObject),
    /// A tagged union and the fields of its selected variant.
    Union {
        /// Explicit wire tag selected by the encoded witness.
        tag: u32,
        /// Declared name associated with `tag`.
        variant: String,
        /// Decoded payload fields.
        value: WitnessObject,
    },
    /// A trailing optional field, either absent or carrying its decoded value.
    Optional(Option<Box<DecodedValue>>),
}

/// One named value in a decoded or to-be-encoded witness object.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedField {
    /// Field name matching the corresponding IDL schema field.
    pub name: String,
    /// Logical field value.
    pub value: DecodedValue,
}

/// Ordered logical representation of witness fields.
///
/// Field order is retained because the linear encoding is order-sensitive.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WitnessObject {
    /// Ordered decoded fields.
    pub fields: Vec<DecodedField>,
}

impl WitnessObject {
    /// Constructs an object from ordered decoded fields.
    pub fn new(fields: Vec<DecodedField>) -> Self {
        Self { fields }
    }

    /// Looks up a decoded value by field name.
    pub fn get(&self, name: &str) -> Option<&DecodedValue> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| &field.value)
    }
}

impl std::ops::Deref for WitnessObject {
    type Target = [DecodedField];

    fn deref(&self) -> &Self::Target {
        &self.fields
    }
}

impl<'a> IntoIterator for &'a WitnessObject {
    type Item = &'a DecodedField;
    type IntoIter = std::slice::Iter<'a, DecodedField>;

    fn into_iter(self) -> Self::IntoIter {
        self.fields.iter()
    }
}

impl IntoIterator for WitnessObject {
    type Item = DecodedField;
    type IntoIter = std::vec::IntoIter<DecodedField>;

    fn into_iter(self) -> Self::IntoIter {
        self.fields.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_object_supports_borrowed_and_owned_iteration() {
        let object = WitnessObject::new(vec![DecodedField {
            name: "nonce".to_string(),
            value: DecodedValue::U16(7),
        }]);

        assert_eq!((&object).into_iter().next().unwrap().name, "nonce");
        let fields: Vec<_> = object.into_iter().collect();
        assert_eq!(fields[0].value, DecodedValue::U16(7));
    }
}
