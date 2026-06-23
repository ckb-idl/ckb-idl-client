/**
 * ckb-idl-registry
 *
 * A minimal off-chain IDL registry that stores and serves IdlDocuments
 * keyed by script code_hash (hex-encoded 32-byte Blake2b-256 hash).
 *
 * Routes
 * ──────
 * GET  /idl/:code_hash   — fetch an IDL by code_hash hex
 * POST /idl/:code_hash   — register an IDL for a given code_hash
 * GET  /health           — health check
 *
 * The store is in-memory. On restart, all registered IDLs are gone.
 * For a persistent registry, swap the Map for a real database.
 */

import express from "express";

export function createApp() {
  const app = express();
  app.use(express.json());

  // ── In-memory store: code_hash_hex → IdlDocument ─────────────────────────
  // Using a plain Map. Keys are lowercase hex strings.
  const store = new Map();

  // ── Validation ────────────────────────────────────────────────────────────

  function isValidCodeHash(hex) {
    return typeof hex === "string" && /^[0-9a-f]{64}$/.test(hex);
  }

  function isValidIdlDocument(doc) {
    if (typeof doc !== "object" || doc === null) return false;
    if (typeof doc.idl_version !== "string") return false;
    if (typeof doc.name !== "string") return false;
    if (!Array.isArray(doc.witness)) return false;

    for (const field of doc.witness) {
      if (typeof field.name !== "string") return false;
      if (typeof field.type !== "string") return false;
      if (typeof field.required !== "boolean") return false;
    }

    return true;
  }

  // ── Routes ────────────────────────────────────────────────────────────────

  // Health check
  app.get("/health", (_req, res) => {
    res.json({ status: "ok", count: store.size });
  });

  app.get("/idl/:code_hash", (req, res) => {
    const code_hash = req.params.code_hash.toLowerCase();

    if (!isValidCodeHash(code_hash)) {
      return res.status(400).json({
        error: "invalid code_hash: must be a 64-character lowercase hex string",
      });
    }

    const doc = store.get(code_hash);
    if (!doc) {
      return res.status(404).json({
        error: `no IDL registered for code_hash ${code_hash}`,
      });
    }

    res.json(doc);
  });

  app.post("/idl/:code_hash", (req, res) => {
    const code_hash = req.params.code_hash.toLowerCase();

    if (!isValidCodeHash(code_hash)) {
      return res.status(400).json({
        error: "invalid code_hash: must be a 64-character lowercase hex string",
      });
    }

    const doc = req.body;
    if (!isValidIdlDocument(doc)) {
      return res.status(422).json({
        error:
          "invalid IdlDocument: must have idl_version (string), name (string), witness (array of {name, type, required})",
      });
    }

    store.set(code_hash, doc);
    res.status(201).json({ registered: code_hash });
  });

  app.get("/idl", (_req, res) => {
    res.json({ code_hashes: [...store.keys()] });
  });

  return app;
}

const isMain = process.argv[1] === new URL(import.meta.url).pathname;
if (isMain) {
  const PORT = process.env.PORT || 3000;
  const app = createApp();
  app.listen(PORT, () => {
    console.log(`ckb-idl-registry listening on http://localhost:${PORT}`);
    console.log(`  GET  /idl/:code_hash   — fetch an IDL`);
    console.log(`  POST /idl/:code_hash   — register an IDL`);
    console.log(`  GET  /health           — health check`);
  });
}
