import {
  AuthSecretKey,
  Felt,
  FeltArray,
  Rpo256,
  Signature,
  type Word,
} from "@miden-sdk/miden-sdk";

const DOMAIN_TRANSFER = 1n;

export interface IntentInput {
  recipientPrefix: bigint;
  recipientSuffix: bigint;
  amount: bigint;
  nonce: bigint;
  expiryBlock: bigint;
}

/** Canonical felt vector — MUST match Rust `Intent::canonical_felts`.
 *
 * Order: [DOMAIN_TRANSFER=1, recipientPrefix, recipientSuffix, amount, nonce, expiryBlock]
 */
export function intentFelts(i: IntentInput): bigint[] {
  return [
    DOMAIN_TRANSFER,
    i.recipientPrefix,
    i.recipientSuffix,
    i.amount,
    i.nonce,
    i.expiryBlock,
  ];
}

/** Hash the canonical felts to the signable Word. */
export function messageWord(felts: bigint[]): Word {
  const elements = felts.map((v) => new Felt(v));
  return Rpo256.hashElements(new FeltArray(elements));
}

/**
 * Serialise a Word as 4 × little-endian u64 bytes = 32 bytes, hex-encoded.
 *
 * This matches Rust's `Word::as_bytes()` which serialises each of the 4
 * field elements as `element.as_canonical_u64().to_le_bytes()`.  The SDK's
 * `Word.toU64s()` returns a `BigUint64Array` in the same element order, so
 * we just write each u64 in little-endian byte order.
 *
 * Note: `Word.toHex()` uses a DIFFERENT encoding (big-endian per-element or
 * Montgomery form) and does NOT match the Rust golden — do not use it for
 * cross-language agreement.
 */
function wordToHex(word: Word): string {
  const u64s = word.toU64s(); // BigUint64Array[4]
  const buf = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let v = u64s[i];
    for (let b = 0; b < 8; b++) {
      buf[i * 8 + b] = Number(v & 0xffn);
      v >>= 8n;
    }
  }
  return bytesToHex(buf);
}

export interface SignResult {
  signatureHex: string;
  publicKeyHex: string;
  messageWordHex: string;
}

/** Sign a transfer intent with an ECDSA-K256-Keccak key. */
export function signIntent(key: AuthSecretKey, i: IntentInput): SignResult {
  const word = messageWord(intentFelts(i));
  const signature: Signature = key.sign(word);
  return {
    signatureHex: bytesToHex(signature.serialize()),
    publicKeyHex: bytesToHex(key.publicKey().serialize()),
    messageWordHex: wordToHex(word),
  };
}

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
