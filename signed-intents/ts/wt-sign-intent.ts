// wasmFetch MUST be the first import: it installs the file:// fetch polyfill
// as a side effect, which must be in place before the SDK's eager entry point
// fires its top-level `await getWasmOrThrow()` at module-evaluation time.
import "./wasmFetch.js";

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { AuthSecretKey } from "@miden-sdk/miden-sdk";
import { signIntent, type IntentInput } from "./signIntent.js";

// Phase B of the two-phase walkthrough:
//   1. Deserialize the secret key persisted by Phase A (wt-export-key.ts).
//   2. Read the Miden account id felts written by Rust after building the account.
//   3. Sign the intent with user_prefix/user_suffix = the account id felts.
//   4. Write { intent, signatureHex, publicKeyHex, messageWordHex } to a fixture file.
//
// Env vars consumed:
//   KEY_IN       — path to the serialized secret key JSON { keyHex } from Phase A.
//   ACCOUNT_ID_IN — path to the account-id JSON { userPrefix, userSuffix } from Rust.
//   FIXTURE_OUT  — path where the signed fixture JSON is written.

const keyInPath = process.env.KEY_IN;
const accountIdInPath = process.env.ACCOUNT_ID_IN;
const fixtureOutPath = process.env.FIXTURE_OUT;

if (!keyInPath || !accountIdInPath || !fixtureOutPath) {
  console.error(
    "Usage: KEY_IN=<path> ACCOUNT_ID_IN=<path> FIXTURE_OUT=<path> tsx wt-sign-intent.ts",
  );
  process.exit(1);
}

// ── Restore the key ──────────────────────────────────────────────────────────
const keyJson = JSON.parse(readFileSync(keyInPath, "utf8")) as {
  keyHex: string;
};
const keyBytes = Uint8Array.from(
  keyJson.keyHex.match(/.{2}/g)!.map((h) => parseInt(h, 16)),
);
// AuthSecretKey.deserialize reconstructs the exact key generated in Phase A.
const key = AuthSecretKey.deserialize(keyBytes);

// ── Read account id felts ────────────────────────────────────────────────────
const accountIdJson = JSON.parse(
  readFileSync(accountIdInPath, "utf8"),
) as { userPrefix: string; userSuffix: string };
// The values are decimal strings representing u64 felts.
const userPrefix = BigInt(accountIdJson.userPrefix);
const userSuffix = BigInt(accountIdJson.userSuffix);

console.log(`[wt-sign-intent] restored key; publicKeyHex = ${[...key.publicKey().serialize()].map((b) => b.toString(16).padStart(2,"0")).join("")}`);
console.log(`[wt-sign-intent] account id userPrefix = ${userPrefix}`);
console.log(`[wt-sign-intent] account id userSuffix = ${userSuffix}`);

// ── Build intent with user_id = account id ───────────────────────────────────
const intent: IntentInput = {
  userPrefix,
  userSuffix,
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

const { signatureHex, publicKeyHex, messageWordHex } = signIntent(key, intent);

// ── Write fixture ─────────────────────────────────────────────────────────────
mkdirSync(dirname(fixtureOutPath), { recursive: true });
writeFileSync(
  fixtureOutPath,
  JSON.stringify(
    {
      intent: {
        user_prefix: accountIdJson.userPrefix,
        user_suffix: accountIdJson.userSuffix,
        recipient_prefix: "0x1234",
        recipient_suffix: "0x5678",
        amount: 1000,
        nonce: 1,
        expiry_block: 500,
      },
      signatureHex,
      publicKeyHex,
      messageWordHex,
    },
    null,
    2,
  ),
);

console.log(`[wt-sign-intent] fixture written to: ${fixtureOutPath}`);
console.log(`[wt-sign-intent] signatureHex = ${signatureHex.slice(0, 16)}...`);
