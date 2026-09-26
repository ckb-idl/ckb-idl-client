//! Errors returned while fetching, verifying, validating, decoding, and encoding IDLs.

use thiserror::Error;

/// All failures reported by the IDL client.
///
/// [`IdlError::category`] and [`IdlError::path`] expose the stable protocol
/// representation used by conformance vectors and cross-language clients.
#[derive(Debug, Error)]
pub enum IdlError {
    /// An HTTP request to the indexer failed at the network/transport level.
    #[error("network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    /// The indexer returned a non-success HTTP status code.
    #[error("HTTP error: status {status}")]
    HttpError { status: u16 },

    /// The response body could not be deserialized as a valid IdlDocument.
    #[error("deserialization error: {0}")]
    DeserializationError(#[from] serde_json::Error),

    /// The SHA-256 hash of the IDL JSON does not match the on-chain commitment.
    #[error("hash mismatch: computed {computed}, expected {expected}")]
    HashMismatch { computed: String, expected: String },

    /// The code cell data is too short to contain the 46-byte IDL binding trailer.
    #[error("insufficient data: code_cell_data has {actual} bytes, need at least 46")]
    InsufficientData { actual: usize },

    /// The code-cell binding trailer is malformed or unsupported.
    #[error("invalid IDL binding trailer: {reason}")]
    InvalidTrailer { reason: &'static str },

    /// JSON bytes are valid JSON but are not the required RFC 8785 artifact.
    #[error("IDL document bytes are valid JSON but are not RFC 8785 canonical bytes")]
    NonCanonicalDocument,

    /// The parsed IDL violates the normative document schema.
    #[error("invalid IDL document at `{path}`: {reason}")]
    InvalidDocument { path: String, reason: String },

    /// A caller-supplied witness object does not match its IDL schema.
    #[error("invalid witness object at `{path}`: {reason}")]
    InvalidObject { path: String, reason: String },

    // ── Witness validation errors ────────────────────────────────────────────
    /// The witness buffer ran out of bytes while decoding a field.
    ///
    /// `path` identifies the logical field. `expected` is how many bytes were needed,
    /// `got` is how many bytes remained in the buffer.
    #[error("witness too short at `{path}`: need {expected} bytes, have {got}")]
    FieldTooShort {
        path: String,
        expected: usize,
        got: usize,
    },

    /// The IDL contains a type string that this client does not know how to decode.
    ///
    /// This means the IDL was produced by a newer version of `ckb-idl-derive` that
    /// added type support not yet present in this client.
    #[error("unknown IDL type `{type_}` at `{path}`")]
    UnknownType { path: String, type_: String },

    /// A low-level field schema is missing metadata required for decoding.
    #[error("invalid schema at `{path}`: {reason}")]
    InvalidFieldSchema { path: String, reason: &'static str },

    /// An encoded vector contains a prohibited element count.
    #[error("vector at `{path}` has invalid element count {count}")]
    InvalidVectorCount { path: String, count: usize },

    /// A union tag does not identify a declared variant.
    #[error("unknown union tag {tag} at `{path}`")]
    UnknownUnionTag { path: String, tag: u32 },

    /// A length prefix cannot represent a valid field span.
    #[error("invalid length at `{path}`")]
    InvalidLength { path: String },

    /// A cursor or encoded-length calculation exceeded the platform size.
    #[error("integer overflow while decoding `{path}`")]
    IntegerOverflow { path: String },

    /// All declared fields decoded successfully but bytes remain unconsumed
    /// in the witness buffer. Indicates the witness has more data than the IDL
    /// describes — likely a version mismatch or wrong IDL.
    #[error("witness has {trailing} trailing bytes after all {field_count} fields were decoded")]
    TrailingBytes {
        path: String,
        trailing: usize,
        field_count: usize,
    },

    /// The document uses an unsupported IDL version.
    #[error("unsupported IDL version `{version}`")]
    UnsupportedVersion { version: String },

    #[error("IDL document has no witness_args.lock interface")]
    MissingLockWitnessInterface,

    #[error("IDL document contains more than one witness_args.lock interface")]
    DuplicateLockWitnessInterface,

    #[error("unsupported encoding profile `{encoding}`")]
    UnsupportedEncoding { path: String, encoding: String },

    #[error("no verified IDL cached for code hash {code_hash}")]
    DocumentNotVerified { code_hash: String },
}

impl IdlError {
    /// Returns the stable snake-case error category defined by IDL 0.1.0.
    pub fn category(&self) -> &'static str {
        match self {
            Self::NetworkError(_) => "network_error",
            Self::HttpError { .. } => "http_error",
            Self::DeserializationError(_) | Self::InvalidDocument { .. } => "invalid_document",
            Self::HashMismatch { .. } => "commitment_mismatch",
            Self::InsufficientData { .. } | Self::InvalidTrailer { .. } => "invalid_trailer",
            Self::NonCanonicalDocument => "non_canonical_document",
            Self::InvalidObject { .. } => "invalid_object",
            Self::FieldTooShort { .. } => "field_too_short",
            Self::UnknownType { .. } => "unknown_type",
            Self::InvalidFieldSchema { .. } => "invalid_document",
            Self::InvalidVectorCount { .. } => "invalid_vector_count",
            Self::UnknownUnionTag { .. } => "unknown_union_tag",
            Self::InvalidLength { .. } => "invalid_length",
            Self::IntegerOverflow { .. } => "integer_overflow",
            Self::TrailingBytes { .. } => "trailing_bytes",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::MissingLockWitnessInterface | Self::DuplicateLockWitnessInterface => {
                "unsupported_interface"
            }
            Self::UnsupportedEncoding { .. } => "unsupported_encoding",
            Self::DocumentNotVerified { .. } => "document_not_verified",
        }
    }

    /// Returns the RFC 6901 logical or document path associated with the error.
    ///
    /// Whole-document and whole-buffer errors return the empty string.
    pub fn path(&self) -> &str {
        match self {
            Self::InvalidDocument { path, .. }
            | Self::InvalidObject { path, .. }
            | Self::FieldTooShort { path, .. }
            | Self::UnknownType { path, .. }
            | Self::InvalidFieldSchema { path, .. }
            | Self::InvalidVectorCount { path, .. }
            | Self::UnknownUnionTag { path, .. }
            | Self::InvalidLength { path }
            | Self::IntegerOverflow { path }
            | Self::TrailingBytes { path, .. }
            | Self::UnsupportedEncoding { path, .. } => path,
            Self::UnsupportedVersion { .. } => "/idl_version",
            Self::MissingLockWitnessInterface | Self::DuplicateLockWitnessInterface => {
                "/interfaces"
            }
            _ => "",
        }
    }
}
    /// The document has no `witness_args.lock` interface.
    /// The document has more than one `witness_args.lock` interface.
    /// The selected interface uses an unsupported encoding profile.
    /// No commitment-verified document is cached under the requested code hash.
