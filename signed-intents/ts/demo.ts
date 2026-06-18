import { AuthSecretKey } from "@miden-sdk/miden-sdk";
import { signIntent, type IntentInput } from "./signIntent.js";

const intent: IntentInput = {
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

const key = AuthSecretKey.ecdsaWithRNG();
const signed = signIntent(key, intent);

console.log(JSON.stringify({ intent: serializeIntent(intent), ...signed }, null, 2));

function serializeIntent(i: IntentInput) {
  return Object.fromEntries(Object.entries(i).map(([k, v]) => [k, (v as bigint).toString()]));
}
