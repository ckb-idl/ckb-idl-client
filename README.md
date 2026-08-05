# ckb-idl-client

A Rust client library for the CKB IDL system. It verifies that a script's on-chain IDL commitment matches a local IDL file, then structurally validates a proposed witness buffer before a transaction is submitted.

This is the wallet/tooling side of the IDL system. The script side is [`ckb-idl-derive`](https://github.com/your-org/ckb-idl-derive).

---

## What problem this solves

CKB lock scripts receive their spending conditions through a `WitnessArgs` field. The field is raw bytes — the VM knows the format, but wallets and tooling don't, unless they have out-of-band knowledge of the script. This means:

- A wallet building a transaction for an unknown script has to guess the witness encoding.
- If the encoding is wrong, the transaction fails with a VM error code — not a user-friendly message.
- There is no machine-readable way to discover what a script expects.

The IDL system fixes this. A script author annotates their witness struct with `#[derive(CkbWitness)]`, which generates an `idl.json` describing the fields. At deployment time, a SHA-256 hash of that JSON is appended to the code cell data. Any client holding the IDL file can verify it matches the on-chain commitment and know with certainty that the IDL describes the deployed code.

---

## Architecture

The system has three tiers:

**Tier 0 — IDL commitment verification**
Fetch the code cell data, extract the last 32 bytes (the IDL commitment), and compare it against `SHA-256(idl.json)`. If they match, the IDL is authentic — it describes the exact code that is deployed.

**Tier 1 — Structural validation (PSCT)**
Parse the proposed witness bytes field-by-field according to the IDL's declared types. This checks that the wire encoding is well-formed: correct lengths, correct field order, no trailing bytes. This is Pre-Submission Correctness Testing — it runs before any network call.

**Tier 2 — Semantic validation**
Enforced by the VM on-chain. Whether a signature is valid, whether a timelock has passed — these are semantic checks. The IDL client does not and cannot perform them.

---

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
ckb-idl-client = { path = "../ckb-idl-client" }
```

### Verify the IDL commitment

```rust
use ckb_idl_client::IdlClient;

let mut client = IdlClient::new();

// code_hash: the blake2b-256 hash of the code cell data (used to identify the script)
// idl_json_bytes: the contents of the frozen IDL file from deployment
// code_cell_data: the raw bytes of the deployed code cell (binary + appended IDL hash)
client.verify(code_hash, &idl_json_bytes, &code_cell_data)?;

println!("IDL is authentic.");
```

### Validate a witness before submitting a transaction

```rust
use ckb_idl_client::{IdlClient, IdlDocument};

let idl_doc: IdlDocument = serde_json::from_slice(&idl_json_bytes)?;
let client = IdlClient::new();

// wire: the raw bytes you intend to put in WitnessArgs.lock
let validated = client.validate_witness_bytes(&idl_doc.witness, &wire)?;

for field in &validated {
    println!("{} ({}): {:?}", field.name, field.type_, field.value);
}
// If this returns Ok, the encoding is structurally valid. Submit the transaction.
```

### Full example: simple-lock

```rust
// Preimage: "hello"
let preimage = b"hello";

// Wire encoding for a "bytes" field: 4-byte LE length prefix + payload
let mut wire = Vec::new();
wire.extend_from_slice(&(preimage.len() as u32).to_le_bytes());
wire.extend_from_slice(preimage);

// Validate against the IDL before building the transaction
let validated = client.validate_witness_bytes(&idl_doc.witness, &wire)?;
// => Ok([ValidatedField { name: "preimage", type_: "bytes", value: Bytes([104,101,108,108,111]) }])
```

---

## Wire format

The wire format is defined by `ckb-idl-derive`'s generated `from_witness_args` implementation. It is sequential, with no envelope framing:

| IDL type           | Wire encoding                                      |
|--------------------|---------------------------------------------------|
| `uint8`            | 1 byte                                             |
| `uint32`           | 4 bytes, little-endian                             |
| `uint64`           | 8 bytes, little-endian                             |
| `secp256k1_sig`    | 65 bytes, fixed                                    |
| `secp256k1_pubkey` | 33 bytes, fixed                                    |
| `schnorr_sig`      | 64 bytes, fixed                                    |
| `bytes`            | 4-byte LE length prefix, then that many bytes      |

Fields are decoded in declaration order. Any trailing bytes after all fields are consumed are an error.

---

## IDL commitment scheme

At deployment time:

```
code_cell_data = risc_v_binary || sha256(idl.json)
```

The deployer writes the exact IDL bytes used to `{script_name}-idl.deployed.json` immediately after computing the hash. This frozen file is what subsequent `verify()` calls should use — not the live generated file, which may be regenerated by `cargo build`.

At spend time:

```
sha256(idl_json_bytes) == code_cell_data[-32:]
```

---

## Error types

`IdlError` covers every failure case:

| Variant           | Meaning                                                        |
|-------------------|----------------------------------------------------------------|
| `InsufficientData`| Code cell data is shorter than 32 bytes                        |
| `HashMismatch`    | IDL file hash does not match the on-chain commitment           |
| `JsonParse`       | IDL JSON is malformed                                          |
| `UnknownType`     | A field uses a type string not known to this decoder           |
| `FieldTooShort`   | Buffer exhausted before a field was fully decoded              |
| `TrailingBytes`   | Extra bytes remain after all fields are decoded                |
| `HttpError`       | HTTP error when fetching IDL from a registry                   |

---

## Test vectors

`test-vectors.json` at the crate root is a canonical, language-independent specification of the wire format. It contains 16 named cases covering every field type, every error condition, and both supported scripts.

Any reimplementation of the decoder (TypeScript, Python, Go) must produce identical results for every vector. The Rust test `test_vectors_file` loads and runs them automatically.

To run the tests:

```bash
cargo test --lib
```

---

## IDL document format

The IDL JSON produced by `ckb-idl-derive` and consumed by this client:

```json
{
  "witness": [
    {
      "name": "signature",
      "type": "secp256k1_sig",
      "required": true,
      "description": "ECDSA signature over the transaction hash"
    },
    {
      "name": "unlock_after_ms",
      "type": "uint64",
      "required": true
    },
    {
      "name": "extra",
      "type": "bytes",
      "required": false,
      "description": "Optional auxiliary payload"
    }
  ]
}
```

`idl_version`, `name`, `description`, `script_version`, and `signing` are optional top-level fields. The client accepts documents with or without them.

---

## Status

This is a pre-publication research implementation. The wire format, commitment scheme, and type registry are stable enough to write reimplementations against, but the API surface may change before a 1.0 release.

The test vectors file is the normative specification. The prose in this README is informative.
