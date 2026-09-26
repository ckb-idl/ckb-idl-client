pub mod client;
pub mod error;
pub mod interface;
pub mod types;

pub use crate::client::IdlClient;
pub use crate::error::IdlError;
pub use crate::types::{
    DecodedField, DecodedValue, IdlDocument, IdlInterface, InterfaceKind, SigningInfo,
    ValidatedField, WitnessField, WitnessObject,
};

pub type Result<T> = std::result::Result<T, IdlError>;
