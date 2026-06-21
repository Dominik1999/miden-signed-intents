// wasmFetch MUST be the first import: it installs the file:// fetch polyfill
// as a side effect, which must be in place before the SDK's eager entry point
// fires its top-level `await getWasmOrThrow()` at module-evaluation time.
import "./wasmFetch.js";

import { writeFileSync, mkdirSync } from "node:fs";
import { AuthSecretKey } from "@miden-sdk/miden-sdk";
import { signIntent, type IntentInput } from "./signIntent.js";

const intent: IntentInput = {
  userPrefix: 0xAAAAn,
  userSuffix: 0xBBBBn,
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

const key = AuthSecretKey.ecdsaWithRNG();
const { signatureHex, publicKeyHex, messageWordHex } = signIntent(key, intent);

mkdirSync("../tests/fixtures", { recursive: true });
writeFileSync(
  "../tests/fixtures/intent_signed.json",
  JSON.stringify(
    {
      intent: {
        user_prefix: "0xAAAA", user_suffix: "0xBBBB",
        recipient_prefix: "0x1234", recipient_suffix: "0x5678",
        amount: 1000, nonce: 1, expiry_block: 500,
      },
      signatureHex, publicKeyHex, messageWordHex,
    },
    null, 2,
  ),
);
console.log("wrote tests/fixtures/intent_signed.json");
