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
    Struct(Vec<ValidatedField>),
    /// A tagged union and the fields of its selected variant.
    Union {
        tag: u32,
        variant: String,
        fields: Vec<ValidatedField>,
    },
    /// A trailing optional field that is absent because the input is exhausted.
    Optional(Option<Box<DecodedValue>>),
}

/// One structurally validated witness field.
///
/// A `ValidatedField` is only produced for fields that decoded successfully.
/// If any required field fails to decode, `validate_witness_bytes` returns
/// an error before producing any output.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedField {
    /// The field name from the IDL.
    pub name: String,
    /// The IDL type string (e.g. `"secp256k1_sig"`, `"uint64"`, `"bytes"`).
    pub type_: String,
    /// Whether this field was marked required in the IDL.
    pub required: bool,
    /// The decoded bytes/value.
    pub value: DecodedValue,
}
