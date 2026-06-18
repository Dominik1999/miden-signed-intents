// @vitest-environment node
import { describe, it, expect } from "vitest";
import { intentFelts, messageWord, signIntent, wordToHex } from "./signIntent.js";
import { AuthSecretKey, PublicKey, Signature } from "@miden-sdk/miden-sdk";

const SAMPLE = {
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

// Frozen in Task 3 from the Rust golden run. Cross-language agreement check.
// Rust Word::as_bytes() = 4 × little-endian u64 values concatenated, hex-encoded.
const GOLDEN_WORD_HEX =
  "ead149459c102c63dffeadd553e3bd50ae48d32af53267ad42eb49c0382a3136";

describe("signed intent", () => {
  it("encodes canonical felts in the agreed order", () => {
    expect(intentFelts(SAMPLE)).toEqual([1n, 0x1234n, 0x5678n, 1000n, 1n, 500n]);
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
