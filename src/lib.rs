pub mod client;
pub mod error;
pub mod types;

pub use crate::client::IdlClient;
pub use crate::error::IdlError;
pub use crate::types::{IdlDocument, SigningInfo, WitnessField};

pub type Result<T> = std::result::Result<T, IdlError>;
