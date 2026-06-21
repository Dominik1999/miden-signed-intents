// wasmFetch MUST be the first import: it installs the file:// fetch polyfill
// as a side effect, which must be in place before the SDK's eager entry point
// fires its top-level `await getWasmOrThrow()` at module-evaluation time.
import "./wasmFetch.js";

import { writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { AuthSecretKey } from "@miden-sdk/miden-sdk";

// Phase A of the two-phase walkthrough:
//   1. Generate a fresh ECDSA-K256-Keccak key.
//   2. Serialize the secret key bytes to a temp file so Phase B can reconstruct it.
//   3. Export the public key hex to a second temp file for Rust to build the account.
//
// Temp file paths are passed via env vars:
//   KEY_OUT   — path for the serialized secret key (hex-encoded Uint8Array).
//   PUBKEY_OUT — path for the public key JSON { publicKeyHex }.

const keyOutPath = process.env.KEY_OUT;
const pubkeyOutPath = process.env.PUBKEY_OUT;

if (!keyOutPath || !pubkeyOutPath) {
  console.error("Usage: KEY_OUT=<path> PUBKEY_OUT=<path> tsx wt-export-key.ts");
  process.exit(1);
}

const key = AuthSecretKey.ecdsaWithRNG();

// Serialize the secret key so Phase B can reconstruct the exact same key.
// AuthSecretKey.serialize() returns Uint8Array; we hex-encode it for portability.
const keyBytes = key.serialize();
const keyHex = [...keyBytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const pubkeyBytes = key.publicKey().serialize();
const publicKeyHex = [...pubkeyBytes]
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");

mkdirSync(dirname(keyOutPath), { recursive: true });
mkdirSync(dirname(pubkeyOutPath), { recursive: true });

writeFileSync(keyOutPath, JSON.stringify({ keyHex }, null, 2));
writeFileSync(pubkeyOutPath, JSON.stringify({ publicKeyHex }, null, 2));

console.log(`[wt-export-key] serialized key written to: ${keyOutPath}`);
console.log(`[wt-export-key] public key written to:     ${pubkeyOutPath}`);
console.log(`[wt-export-key] publicKeyHex = ${publicKeyHex}`);
