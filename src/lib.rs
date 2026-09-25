pub mod client;
pub mod error;
pub mod types;
pub mod interface;

pub use crate::client::IdlClient;
pub use crate::error::IdlError;
pub use crate::types::{
    DecodedValue, IdlDocument, SigningInfo, ValidatedField, WitnessField, IdlInterface, InterfaceKind,
};

pub type Result<T> = std::result::Result<T, IdlError>;
