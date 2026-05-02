// IdlClient will be implemented in tasks 4, 6, 7

use crate::{IdlDocument, Result, WitnessField};
use std::collections::HashMap;

/// Compute a 32-byte BLAKE2b-256 digest of the given bytes.
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub struct IdlClient {
    pub http: reqwest::Client,
    pub cache: HashMap<[u8; 32], IdlDocument>,
}

impl IdlClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            cache: HashMap::new(),
        }
    }

    pub async fn fetch(&self, indexer_url: &str, code_hash: [u8; 32]) -> Result<IdlDocument> {
        if let Some(doc) = self.cache.get(&code_hash) {
            return Ok(doc.clone());
        }
        let url = format!("{}/idl/{}", indexer_url, hex::encode(code_hash));
        let res = self.http.get(&url).send().await?;

        if !res.status().is_success() {
            return Err(crate::IdlError::HttpError {
                status: res.status().as_u16(),
            });
        }

        let doc = res.json::<IdlDocument>().await?;

        Ok(doc)
    }

    pub fn verify(
        &mut self,
        code_hash: [u8; 32],
        idl_json_bytes: &[u8],
        code_cell_data: &[u8],
    ) -> Result<()> {
        if code_cell_data.len() < 32 {
            return Err(crate::IdlError::InsufficientData {
                actual: code_cell_data.len(),
            });
        }
        let idl_hash = &code_cell_data[code_cell_data.len() - 32..];

        let idl_json_bytes_hash = blake2b_256(idl_json_bytes);
        let idl_json_bytes_hash_as_bytes = idl_json_bytes_hash;

        if idl_json_bytes_hash_as_bytes != idl_hash {
            return Err(crate::IdlError::HashMismatch {
                computed: hex::encode(idl_json_bytes_hash_as_bytes),
                expected: hex::encode(idl_hash),
            });
        }

        let doc: IdlDocument = serde_json::from_slice(idl_json_bytes)?;
        self.cache.insert(code_hash, doc);
        Ok(())
    }

    pub async fn witness_requirements(
        &self,
        indexer_url: &str,
        code_hash: [u8; 32],
    ) -> Result<Vec<WitnessField>> {
        let doc = if let Some(doc) = self.cache.get(&code_hash) {
            doc.clone()
        } else {
            self.fetch(indexer_url, code_hash).await?
        };


        let witness_fields = doc.witness;

        Ok(witness_fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_minimal() {
        let doc_json = r#"{"idl_version":"","name":"","witness":[]}"#;
        let idl_json_bytes = doc_json.as_bytes();
        let hash = blake2b_256(idl_json_bytes);
        let mut code_cell_data: Vec<u8> = vec![];
        code_cell_data.extend_from_slice(&hash);

        let mut client = IdlClient::new();
        let result = client.verify([0u8; 32], idl_json_bytes, &code_cell_data);
        assert!(result.is_ok(), "verify failed: {:?}", result);
    }
}
