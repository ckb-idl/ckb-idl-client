use thiserror::Error;

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

    /// The blake2b-256 hash of the IDL JSON does not match the on-chain commitment.
    #[error("hash mismatch: computed {computed}, expected {expected}")]
    HashMismatch { computed: String, expected: String },

    /// The code cell data is too short to contain a 32-byte IDL commitment.
    #[error("insufficient data: code_cell_data has {actual} bytes, need at least 32")]
    InsufficientData { actual: usize },

    // ── Witness validation errors ────────────────────────────────────────────

    /// The witness buffer ran out of bytes while decoding a field.
    ///
    /// `field` is the IDL field name. `expected` is how many bytes were needed,
    /// `got` is how many bytes remained in the buffer.
    #[error(
        "witness too short for field `{field}`: need {expected} bytes, have {got}"
    )]
    FieldTooShort {
        field: String,
        expected: usize,
        got: usize,
    },

    /// The IDL contains a type string that this client does not know how to decode.
    ///
    /// This means the IDL was produced by a newer version of `ckb-idl-derive` that
    /// added type support not yet present in this client.
    #[error("unknown IDL type `{type_}` for field `{field}`")]
    UnknownType { field: String, type_: String },

    /// All declared fields decoded successfully but bytes remain unconsumed
    /// in the witness buffer. Indicates the witness has more data than the IDL
    /// describes — likely a version mismatch or wrong IDL.
    #[error(
        "witness has {trailing} trailing bytes after all {field_count} fields were decoded"
    )]
    TrailingBytes {
        trailing: usize,
        field_count: usize,
    },

    /// Unsupported IDL version
    #[error("unsupported IDL version `{version}`")]
    UnsupportedVersion {
        version: String,
    },

    #[error("IDL document has no witness_args.lock interface")]
    MissingLockWitnessInterface,

    #[error("IDL document contains more than one witness_args.lock interface")]
    DuplicateLockWitnessInterface,

    #[error("unsupported encoding profile `{encoding}`")]
    UnsupportedEncoding {
        encoding: String
    },

    #[error("no verified IDL cached for code hash {code_hash}")]
    DocumentNotVerified {
        code_hash: String,
    },
}
