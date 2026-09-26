//! Verification, parsing, and witness encoding for CKB IDL 0.1.0.
//!
//! The crate separates untrusted parsing from commitment verification. Use
//! [`IdlClient::verify_and_cache`] or [`IdlClient::fetch_verify_and_cache`] when
//! an IDL must be authenticated against code-cell data.

#![warn(missing_docs)]

/// Registry access, commitment verification, and witness codecs.
pub mod client;
/// Public error types and stable error categories.
pub mod error;
/// IDL document validation and interface selection.
pub mod interface;
/// IDL documents and the ordered client object model.
pub mod types;

pub use crate::client::IdlClient;
pub use crate::error::IdlError;
pub use crate::types::{
    DecodedField, DecodedValue, IdlDocument, IdlInterface, InterfaceKind, SigningInfo,
    WitnessField, WitnessObject,
};

/// Result type returned by this crate.
pub type Result<T> = std::result::Result<T, IdlError>;
