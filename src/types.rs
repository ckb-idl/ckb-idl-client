use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdlDocument {
    pub idl_version: String,
    pub name: String,
    pub witness: Vec<WitnessField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningInfo>,
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
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
