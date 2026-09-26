use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdlDocument {
    pub idl_version: String,
    pub interfaces: Vec<IdlInterface>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdlInterface {
    pub id: String,
    pub kind: InterfaceKind,
    pub encoding: EncodingProfile,
    pub fields: Vec<WitnessField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceKind {
    #[serde(rename = "witness_args.lock")]
    WitnessArgsLock,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodingProfile {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigningInfo {
    pub algorithm: String,
    pub message: String,
    pub hasher: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessField {
    pub name: String,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_type: Option<String>,

    pub required: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<VectorItem>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<WitnessField>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub variants: Option<Vec<UnionVariant>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorItem {
    #[serde(rename = "type")]
    pub type_: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnionVariant {
    pub tag: u32,
    pub name: String,
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
        tag: u32,
        variant: String,
        value: WitnessObject,
    },
    /// A trailing optional field, either absent or carrying its decoded value.
    Optional(Option<Box<DecodedValue>>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedField {
    pub name: String,
    pub value: DecodedValue,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct WitnessObject {
    pub fields: Vec<DecodedField>,
}

impl WitnessObject {
    pub fn new(fields: Vec<DecodedField>) -> Self {
        Self { fields }
    }

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
