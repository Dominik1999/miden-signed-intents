// @vitest-environment node
import { describe, it, expect } from "vitest";
import { intentFelts, messageWord, signIntent, wordToHex } from "./signIntent.js";
import { AuthSecretKey, PublicKey, Signature } from "@miden-sdk/miden-sdk";

const SAMPLE = {
  userPrefix: 0xAAAAn,
  userSuffix: 0xBBBBn,
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

// Cross-language agreement: must equal the Rust golden (tests/golden.rs).
const GOLDEN_WORD_HEX =
  "cd14e20aa24e67a4a0d09293e885236caaaa22d4e858ae04a9015a9fcf045e70";

describe("signed intent", () => {
  it("encodes canonical felts in the agreed order", () => {
    expect(intentFelts(SAMPLE)).toEqual([1n, 0xAAAAn, 0xBBBBn, 0x1234n, 0x5678n, 1000n, 1n, 500n]);
  });

  it("hashes to the same Word as the Rust side", () => {
    const word = messageWord(intentFelts(SAMPLE));
    expect(wordToHex(word)).toBe(GOLDEN_WORD_HEX);
  });

  it("produces a signature that verifies under its own public key", () => {
    const key = AuthSecretKey.ecdsaWithRNG();
    const { signatureHex, publicKeyHex, messageWordHex } = signIntent(key, SAMPLE);
    expect(messageWordHex).toBe(GOLDEN_WORD_HEX);
    const pk = PublicKey.deserialize(hexToBytes(publicKeyHex));
    const sig = Signature.deserialize(hexToBytes(signatureHex));
    expect(pk.verify(messageWord(intentFelts(SAMPLE)), sig)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  return new Uint8Array(s.match(/.{1,2}/g)!.map((x) => parseInt(x, 16)));
}
