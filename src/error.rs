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
}
