# ckb-idl-client

`ckb-idl-client` is the wallet and transaction-builder implementation of CKB
IDL 0.1.0. It can:

- fetch exact IDL bytes from a registry;
- verify those bytes against an IDL commitment in code-cell data;
- validate the IDL document and its recursive witness schema;
- decode `WitnessArgs.lock` bytes into an ordered logical object; and
- encode that object back into the exact linear wire representation.

The crate performs structural validation. Signature validity, timelocks,
commitments, and other script-specific semantics remain the responsibility of
the CKB script.

## Status

This project is pre-release. The implemented protocol target is IDL 0.1.0, but
the Rust API can still change before the compatible crates and specification
are tagged.

Current scope is one `witness_args.lock` interface using
`ckb-idl-linear-0.1.0`. Script args, other `WitnessArgs` fields, type-script and
cell-data interfaces, Molecule encoding, and type-hash-aware code-cell identity
are future work.

## Installation

During development, add the local crate:

```toml
[dependencies]
ckb-idl-client = { path = "../ckb-idl-client" }
```

The asynchronous registry methods require a Tokio runtime.

## Trust model

IDL discovery and IDL authority are separate:

```text
registry response bytes                 untrusted
        ↓
Binding Trailer 1 digest verification   authenticates exact IDL bytes
        ↓
IDL parsing and document validation     authenticates document structure
        ↓
private verified cache                  safe requirements lookup
```

`parse_document()` only parses. `fetch_bytes()` only retrieves bytes. Neither
operation authenticates an IDL.

Use `verify_and_cache()` or `fetch_verify_and_cache()` when the result will be
trusted:

```rust,no_run
use ckb_idl_client::IdlClient;

# async fn example(
#     registry_url: &str,
#     code_hash: [u8; 32],
#     code_cell_data: Vec<u8>,
# ) -> ckb_idl_client::Result<()> {
let mut client = IdlClient::new();

client
    .fetch_verify_and_cache(registry_url, code_hash, &code_cell_data)
    .await?;

let fields = client.lock_witness_requirements(code_hash)?;
println!("{} witness fields", fields.len());
# Ok(())
# }
```

The caller must currently supply the code-cell data resolved for `code_hash`.
The client verifies the IDL commitment inside those bytes, but it does not yet
prove the CKB code-hash lookup relation. Data-hash verification and later
version-aware `hash_type = type` support are tracked separately.

## Exact-byte commitment

IDL 0.1.0 uses RFC 8785 canonical JSON and raw SHA-256 over the exact artifact
bytes. Binding Trailer 1 is appended to the executable:

```text
code_cell_data = executable || payload || payload_len_u32_le || magic

payload = version_u8 || flags_u8 || sha256(canonical_idl_bytes)
version = 1
flags = 0
payload_len = 34
magic = "CKBIDL\0\0"
```

The complete trailer is 46 bytes. Verification rejects unknown versions,
unknown flags, incorrect payload lengths, incorrect magic, noncanonical JSON,
and digest mismatches.

Commitment tooling must preserve the frozen canonical IDL bytes. It must not
pretty-print, trim, or silently reserialize the document before hashing.

## IDL document model

An IDL 0.1.0 document contains exactly one supported interface:

```json
{
  "idl_version": "0.1.0",
  "interfaces": [
    {
      "id": "lock_witness",
      "kind": "witness_args.lock",
      "encoding": { "id": "ckb-idl-linear-0.1.0" },
      "fields": [
        {
          "name": "signature",
          "type": "secp256k1_sig",
          "wire_type": "bytes_fixed_65",
          "required": true,
          "description": "Signature authorizing the spend"
        },
        {
          "name": "memo",
          "type": "bytes",
          "required": false
        }
      ]
    }
  ]
}
```

The formatted JSON above is illustrative. A committed artifact must use RFC
8785 canonical bytes.

`type` carries either structural meaning or wallet-facing semantic meaning.
`wire_type` is required only when `type` is semantic. For example,
`secp256k1_sig` uses `bytes_fixed_65`. Structural types must not redundantly
provide `wire_type`.

Document validation also enforces:

- ASCII identifiers;
- unique field and union-variant names;
- required fields before trailing optional fields;
- nonempty structs, union variant lists, union payloads, and encoded vectors;
- unique union tags sorted in ascending order;
- conditional `items`, `fields`, and `variants` metadata; and
- the supported typed-vector element set.

## Linear encoding

Fields are encoded sequentially in declaration order.

| Structural type | Encoding |
|---|---|
| `uint8` | one byte |
| `uint16`, `uint32`, `uint64`, `uint128` | little-endian unsigned integer |
| `bytes_fixed_N` | exactly `N` bytes |
| `bytes` | `u32` little-endian byte length, then payload |
| `vector` | `u32` little-endian element count, then fixed-size elements |
| `struct` | child fields in declaration order |
| `union` | `u32` little-endian tag, then selected payload fields |

Typed vectors support `uint16`, `uint32`, `uint64`, `uint128`, and
`bytes_fixed_N`. `Vec<u8>` is represented as `bytes`, not `vector<uint8>`.

Optional fields are represented by `required: false`, must be trailing, and
are absent by buffer exhaustion. Empty `bytes` remains distinguishable from an
absent optional field because present bytes always include a four-byte length.

Trailing witness bytes are rejected.

## Decoding witnesses

`decode_lock_witness()` validates the document and returns an ordered
`WitnessObject`:

```rust
use ckb_idl_client::{DecodedValue, IdlClient, IdlDocument};

# fn example(
#     idl_bytes: &[u8],
#     witness_lock: &[u8],
# ) -> ckb_idl_client::Result<()> {
let document: IdlDocument = IdlClient::parse_document(idl_bytes)?;
let client = IdlClient::new();
let object = client.decode_lock_witness(&document, witness_lock)?;

if let Some(DecodedValue::Bytes(signature)) = object.get("signature") {
    println!("signature has {} bytes", signature.len());
}
# Ok(())
# }
```

Nested structs contain another `WitnessObject`. Unions retain their numeric tag,
declared variant name, and payload object. Optional fields decode to
`Optional(None)` or `Optional(Some(value))`.

## Encoding witnesses

Wallets and transaction builders can construct an object and encode it:

```rust
use ckb_idl_client::{
    DecodedField, DecodedValue, IdlClient, IdlDocument, WitnessObject,
};

# fn example(document: &IdlDocument) -> ckb_idl_client::Result<Vec<u8>> {
let object = WitnessObject::new(vec![
    DecodedField {
        name: "signature".into(),
        value: DecodedValue::Bytes(vec![0u8; 65]),
    },
    DecodedField {
        name: "memo".into(),
        value: DecodedValue::Optional(None),
    },
]);

let wire = IdlClient::new().encode_lock_witness(document, &object)?;
# Ok(wire)
# }
```

Encoding rejects missing, unknown, out-of-order, incorrectly typed, or
incorrectly sized values. A present optional field cannot follow an absent one.

## Stable errors and paths

Every `IdlError` exposes a stable category and RFC 6901 path:

```rust
# fn show(error: ckb_idl_client::IdlError) {
println!("{} at {}", error.category(), error.path());
# }
```

Examples:

```text
field_too_short at /signature
field_too_short at /authorization/value/signature
field_too_short at /signatures/1
invalid_document at /interfaces/0/fields/1/type
trailing_bytes at ""
```

The stable categories and paths are shared by the language-independent
conformance vectors.

## Conformance

Versioned copies of the IDL 0.1.0 normative fixtures live under
`tests/fixtures/idl-0.1.0`. The test suite checks:

- successful scalar and recursive decoding;
- byte-for-byte object re-encoding;
- malformed witness categories and paths;
- malformed document categories and paths;
- RFC 8785 canonicalization behavior;
- canonical example SHA-256 hashes; and
- Binding Trailer 1 verification.

Run all checks with:

```bash
cargo fmt --all -- --check
cargo test --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

## Repository roles

- `ckb-idl-spec`: normative schema, encoding, errors, commitment format, and fixtures.
- `ckb-idl-derive`: Rust witness derives and recursive IDL exporter.
- `ckb-idl-client`: registry retrieval, verification, object decoding, and encoding.

The script registry is a discovery layer. Commitment verification is what lets
clients safely consume a document returned by that registry.
