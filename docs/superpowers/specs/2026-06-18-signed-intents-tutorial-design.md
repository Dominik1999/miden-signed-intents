# Signed Intents on Miden — Tutorial Design Spec

**Date:** 2026-06-18
**Status:** Approved (design); pending spec review
**Audience:** Miden builders ("Pioneers") who know basic accounts/notes/MASM and want to learn the signed-intent pattern.

---

## 1. Goal

Produce a **standalone tutorial** that teaches the *signed intent* pattern on Miden:

> A user authorizes an action by **signing an intent off-chain** (TypeScript, ECDSA).
> A **receiver/relayer** carries that signed intent to an **account that verifies the
> ECDSA signature on-chain in MASM** before acting. Because verification is on-chain,
> the receiver is *bounded*: it can only execute intents the user actually signed —
> it cannot forge, alter, or replay them.

This is the trust upgrade over the perp repo's current design, where the operator verifies the intent **off-chain in Rust** (and therefore must be trusted). Moving verification into the account's MASM removes that trust assumption — "the operator can't cheat."

### Deliverable
1. A **runnable example project** at `signed-intents/` (passes `cargo test` against MockChain — no live node required).
2. A **markdown recipe** following the docs tutorial template, with explanatory prose and copy-pasteable code snippets.

---

## 2. Architecture

```
   USER (off-chain, TypeScript)                RECEIVER / RELAYER (Rust)         CHAIN (MASM)
  ┌──────────────────────────┐               ┌───────────────────────┐       ┌────────────────────────┐
  │ build canonical intent   │   signed      │ deploy authorizer acct│       │ authorizer account     │
  │ felts → Rpo256.hash      │   intent      │ build tx that calls    │  tx   │  proc execute_intent:  │
  │ → AuthSecretKey(ECDSA)   │ ─────────────▶│  execute_intent,       │ ────▶ │  1. rebuild MSG word   │
  │   .sign(word)            │  (intent +    │  push intent as inputs │       │  2. ecdsa verify       │
  │ export sigHex, pkHex     │   sigHex,pkHex)│  push sig+pk as advice│       │  3. nonce + expiry     │
  └──────────────────────────┘               └───────────────────────┘       │  4. record to storage  │
                                                                              └────────────────────────┘
```

- **Account protocol-level auth:** `NoAuth`. Any relayer may *submit* the transaction; **all real authorization lives in `execute_intent`**, which aborts (makes the transaction unprovable) unless a valid, unexpired, non-replayed ECDSA intent signature is present. This is the cleanest demonstration of "the signed intent *is* the authorization."
- **Signature scheme:** ECDSA-K256-Keccak (`AuthScheme::EcdsaK256Keccak`, scheme id `1`) — the same scheme `PerpSigner.newSessionKey()` already uses via `AuthSecretKey.ecdsaWithRNG()`.
- **On-chain verify primitive:** `miden::core::crypto::dsa::ecdsa_k256_keccak::verify` — native core-library precompile, not a hand-rolled secp256k1 routine. Operand stack `[PK_COMMITMENT, MSG, ...]`; the full public key (`9` felts) and signature (`17` felts) are supplied via the **advice provider** by the relayer. *(Exact ABI to be re-confirmed against 0.14 during implementation — see §6.)*

---

## 3. The Intent (data model)

A single canonical field-element vector is hashed to the `Word` that gets signed. **Identical construction in TS and MASM** so signatures match byte-for-byte (the same TS↔Rust discipline the perp repo already follows in `perpSigner.ts` / `sig.rs`).

The intent keeps a transfer-style payload (it reads as a real authorization), but the demonstrated on-chain action is **recording that authorized payload to account storage** rather than emitting an asset note — so the tutorial stays focused on signature verification, not note mechanics.

```
canonical_felts(intent) = [
  DOMAIN_TRANSFER,      // domain-separation tag (constant, e.g. 1)
  recipient_prefix,     // recipient account id (2 felts)
  recipient_suffix,
  amount,               // u64 minor units being authorized
  nonce,                // per-account strictly-increasing replay guard
  expiry_block,         // intent invalid once current block height >= this
]
MSG = Rpo256::hash_elements(canonical_felts)   // the signed Word
```

Design choices and rationale:
- **Domain tag** prevents a signature for one action type being replayed as another (mirrors perp's `DOMAIN_INTENT` etc.).
- **Expiry as block height** (not unix time): block height is trivially available on-chain; wall-clock expiry would require trusting an off-chain clock — defeating the point.
- **Nonce** stored in account storage; `execute_intent` asserts `incoming_nonce > stored_nonce`, then writes it back. Strictly-increasing, per-account.

---

## 4. Components (the three languages)

### 4.1 MASM — `authorizer.masm` (the centerpiece)
Custom account component. Storage:
- slot: `owner_pubkey_commitment` (Word) — the committed ECDSA public key.
- slot: `last_nonce` (Felt) — replay high-water mark.
- slot: `last_authorized` (Word) — record of the most recently executed intent (e.g. `[recipient_prefix, recipient_suffix, amount, nonce]`), the "storage flag" proving the action ran.

Procedure `execute_intent` (exported), inputs on operand stack = the intent fields; sig + full pubkey delivered via advice. Steps:
1. Reconstruct `MSG = hash_elements(canonical_felts)` from the inputs (must match TS exactly).
2. Load `owner_pubkey_commitment` from storage; `exec.ecdsa_k256_keccak::verify` (aborts on bad sig).
3. Assert `nonce > last_nonce`; write `last_nonce = nonce`.
4. Assert `current_block_height < expiry_block` (else abort).
5. Record the authorized payload to the `last_authorized` storage slot. (In production this is where you'd emit the P2ID transfer instead — the tutorial notes this and links the "Create Notes in MASM" recipe, but keeps the action a storage write to stay focused on verification.)

### 4.2 TypeScript — `signIntent.ts` (the user)
Uses `@miden-sdk/miden-sdk` (0.14). Trimmed version of the perp's `perpSigner.ts`:
- `intentFelts(intent)` → canonical felt vector (matching §3).
- `messageWord(felts)` = `Rpo256.hashElements(new FeltArray(...))`.
- `AuthSecretKey.ecdsaWithRNG()` (or load a known key) → `.sign(word)` → `Signature`.
- Export `signatureHex = bytesToHex(sig.serialize())`, `publicKeyHex = bytesToHex(key.publicKey().serialize())`.
- A small `main()` that prints a signed intent the Rust side can consume (and a golden-vector test asserting determinism).

### 4.3 Rust — receiver/relayer + tests (`miden-client` + MockChain)
- **Build** the authorizer account (NoAuth + the `authorizer.masm` component), set `owner_pubkey_commitment` from the user's pubkey.
- **Relay**: build a transaction calling `execute_intent`, pushing intent fields as inputs and decoding the user's `sigHex`/`pkHex` into the advice provider (`9`-felt pubkey + `17`-felt signature).
- **Tests** (MockChain, `cargo test`):
  - *Happy path:* valid intent → transaction proves; the `last_authorized` storage slot and `last_nonce` advance to the signed values.
  - *Adversarial (the anti-cheat proof):*
    - tampered field (relayer bumps `amount`) → verify fails → unprovable.
    - wrong key / forged signature → unprovable.
    - replayed nonce (`nonce <= last_nonce`) → abort.
    - expired intent (`current_block >= expiry_block`) → abort.

---

## 5. Tutorial document (markdown)

Follows the docs **recipe template**:
`Overview` → `What we'll cover` → `Prerequisites` → numbered `Step N` → `Running the example` → `Continue learning`.

- **Overview:** one paragraph framing signed intents and the off-chain-vs-on-chain-verification trust difference.
- **What we'll cover:** signed intents; ECDSA-K256-Keccak; on-chain signature verification in an account component; canonical message hashing across TS/MASM; replay + expiry; the relayer/advice-provider plumbing.
- **Prerequisites:** basic MASM, accounts/notes, the Rust + TS SDKs; links to the Counter, Create-Notes-in-MASM, and account-component recipes.
- **Steps** map 1:1 to §4 (define the intent → write the MASM verifier → sign in TS → relay + verify in Rust → break it on purpose).
- **Running the example:** `cargo test` (and the TS signer demo).
- **Continue learning:** point back to the perp repo and miden-x402 as real-world uses; note the Falcon512 alternative.

---

## 6. Versions & risks

- **Stack pinned:** `miden-client` / `miden-protocol` **0.14**; `@miden-sdk/miden-sdk` **0.14**; core-lib MASM namespace `miden::core::...`.
- **Risk — MASM ABI drift:** the ECDSA module was renamed around Testnet v0.13 (`std::crypto::dsa::ecdsa::secp256k1` → `miden::core::crypto::dsa::ecdsa_k256_keccak`), and `SecretKey`→`SigningKey` in miden-crypto v0.25. **Before writing MASM, re-confirm against 0.14**: exact module path, the operand/advice layout of `verify`, the felt-packing of pubkey (`9`) and signature (`17`), the hash-elements proc, the current-block-height proc, and the storage read/write procs. (Task: "Verify ECDSA MASM ABI on 0.14".)
- **Risk — ECDSA pubkey recovery unsupported:** the SDK's `recoverFrom` is Falcon-only. The design verifies against a **committed** pubkey (stored in the account), not EVM-style recover-from-signature. This is already the design, so no impact.
- **Runnable bar:** MockChain only; no live-node dependency. A live-node walkthrough is explicitly out of scope (could be a follow-up recipe).

## 7. Out of scope (YAGNI)
- Multi-sig / threshold intents.
- A full frontend (only the signer module + a demo `main`).
- Live testnet deployment.
- The cumulative-voucher/batching model from x402 (mention as "further reading," don't build).
