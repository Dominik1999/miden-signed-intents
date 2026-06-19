# Signed Intents on Miden — Redesign Design Spec

**Date:** 2026-06-19
**Status:** Approved (design); implementation pending spike (see §10)
**Tracking issue:** [0xMiden/docs#314](https://github.com/0xMiden/docs/issues/314) — *Example and Tutorial for end-to-end signature flow, for intent-based applications.*

---

## 1. Why this rewrite exists

The current tutorial/example was validated by the Miden team and judged to fail at its one job:
being a **canonical reference for signature-based authorization of Miden accounts**. After ~9 hours
of expert effort the team was "not much closer to implementing the signed orders flow," and concluded
a new developer "would probably be scared away."

The root cause is architectural, not cosmetic:

- The ECDSA (`ecdsa_k256_keccak`) keypair in the TypeScript example is **standalone** — not connected
  to any Miden account.
- The MASM verifier reads a public-key commitment from a **custom storage slot** that the deployer set
  at deploy time; the key is **not** the account's authentication key and has **no authority** over the
  account.
- The account uses `Auth::IncrNonce` — a **mock** auth component — so all "authorization" is bolted on
  beside the real (absent) auth boundary.

Net effect: the example cannot serve as a reference for *intent-based authorization of Miden accounts*,
because the key authorizes nothing about the account and is not part of the account's identity.

Secondary problems: TypeScript test/build fragility, no end-to-end test linking the TS signer to MASM
verification, and tutorial prose that is convoluted and reads as LLM-generated.

## 2. Requirements (from issue #314 + the team thread)

The deliverable must demonstrate, executably and without protocol-level hand-holding:

1. Canonical message construction, **explicit** serialization, hashing, and the exact intermediate values.
2. Signature generation in the **frontend/wallet** and verification in both the **Rust client** and
   **inside the VM (MASM)**.
3. **A way to verify that a public key really belongs to a specific Miden account ID** — verified in
   **both Rust and MASM** (server-side check *before* execution so a doomed transaction is never submitted).
   *(mico, issue thread.)*
4. Handling invalid signatures; using a successful verification to **authorize a real action**.
5. Security discussion: what is signed, replay risk, message uniqueness, recommended patterns, common mistakes.

### Canonical flow (yellowBirdy's 9 steps, adapted)

`build intent → serialize → Poseidon2 hash → sign in TS "wallet" → transport {intent, sig, pubkey, accountId}
→ server verifies off-chain (signature + pubkey↔accountId) → relayer submits tx → account's native ECDSA
auth verifies in-VM → emits P2ID note → nonce/expiry guards reject replays and expired intents.`

## 3. Decisions locked during brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| Frontend/wallet signing | **SDK signer framed as wallet** — `AuthSecretKey(EcdsaK256Keccak).sign()` in a TS/node script | The exact primitive a wallet calls internally; fully executable today, deterministic, no browser/wasm rabbit hole. Satisfies "executable with minimal modification." |
| Authorized action | **Emit a P2ID payment note** paying `amount` of `faucet_id` to `recipient` | Canonical Miden "do something" = create an output note. Moves real value; bounded surface (no full swap engine). |
| Key↔account architecture | **Approach 2 — native auth.** The ECDSA key is the account's auth key; the signature check *is* the account's authorization boundary | Strongest answer to the critique; makes the pubkey part of the account ID (see §5). Accepted with a feasibility spike (§10). |
| Relayer/server | **Kept.** Untrusted relayer submits on the owner's behalf | This is the entire point of the intent pattern; matches the 9-step flow. |

## 4. Canonical message format & serialization

Intent fields, **fixed order** (this ordering is normative and mirrored byte-for-byte in Rust and TS):

```
index  field                type    notes
0      DOMAIN_TRANSFER      felt    domain separation tag (constant)
1      account_id_prefix    felt    user's (payer) Miden account ID, high word
2      account_id_suffix    felt    user's (payer) Miden account ID, low word
3      recipient_prefix     felt    payee Miden account ID, high word
4      recipient_suffix     felt    payee Miden account ID, low word
5      faucet_id            felt    asset faucet ID
6      amount               felt    asset amount
7      nonce                felt    strictly increasing per account
8      expiry               felt    block height; intent invalid at/after this block
```

The payee is a Miden account ID (2 felts). The actual P2ID **RECIPIENT digest** (serial number, note
script root, note inputs) is derived inside the contract from these felts during implementation; the
signed object is this 9-felt vector.

- **Encoding:** Miden field elements (`Felt`, u64 in the Goldilocks field). No floats, no variable-length encoding.
- **Byte/array handling:** fixed-length array of 9 felts; no dynamic arrays at the serialization boundary.
- **`account_id` is a signed field** (indices 1–2): the signature is therefore only valid for one specific
  account, giving domain separation on top of the structural account-ID binding in §5.
- **Serialization boundary:** the 9-felt vector is the canonical signable object. Transport adds
  `{ signatureHex, publicKeyHex, accountId }` around it but those are *not* re-hashed.

A **golden vector** (the exact 9 felts and the resulting digest hex) is published and asserted by tests on
both sides, so cross-language agreement is proven, not assumed.

## 5. Public-key ↔ account-ID binding (the crux)

A Miden account's **ID is derived from its initial code + storage commitments** at creation. When the ECDSA
key is the account's **native auth key**, the pubkey commitment lives in the auth component's storage slot,
so it is cryptographically committed **into the account ID itself**. "Does this pubkey belong to this
account ID?" becomes a structural fact rather than a lookup.

- **In MASM:** the auth procedure verifies the signature against the account's **own** auth-key slot
  (`active_account::get_item`), never a hardcoded constant. The kernel authenticates that slot against the
  account's on-chain commitment, so a passing verification *proves* the signer holds the key bound to **this**
  account ID.
- **In Rust (server, before submission):** fetch the account state by ID, read its auth-key commitment,
  assert it equals `pubkey.to_commitment()`, and verify the ECDSA signature locally over the digest. Only
  then relay. This prevents submitting a transaction that would abort in the VM.

This directly fixes the original defect (key in a side slot beside a mock auth, with no authority over the
account and not part of its identity).

## 6. Component design

### 6.1 Account + native auth
- Account built with a **custom ECDSA auth component**; the ECDSA key is the account's auth key.
- **No `Auth::IncrNonce` mock.** The auth procedure increments the nonce itself.
- Pubkey commitment stored in the auth slot ⇒ bound into the account ID (§5).

### 6.2 MASM auth procedure (`authorizer.masm`)
1. Reconstruct `MSG = Poseidon2::hash(intent_felts)` (rewritten in the clearer style — see §9).
2. Verify the intent signature against the account's **own** auth-key slot (`ecdsa_k256_keccak::verify`).
3. Replay guard: `nonce > last_nonce`. Expiry guard: `current_block < expiry`.
4. Emit the P2ID note **derived from the verified felts** (`recipient`, `faucet_id`, `amount`) — the relayer
   cannot alter recipient/amount because changing any signed felt fails ECDSA verification.
5. Increment the account nonce; persist `last_nonce`.

### 6.3 TypeScript "wallet" signer (`ts/signIntent.ts`)
- Build the 8-felt intent; hash with Poseidon2; `AuthSecretKey(EcdsaK256Keccak).sign(digest)`.
- Output `{ signatureHex, publicKeyHex, accountId }`.
- Framed in prose as "this is what your wallet does on sign."

### 6.4 Rust server / relayer (`src/relayer.rs`)
- **Off-chain verification first:** verify signature over the digest under `pubkey`; assert
  `account.auth_key_commitment == pubkey.to_commitment()`. Reject before submission on any failure.
- Then assemble the transaction (push intent felts, inject recovered signature into advice) and relay it
  against MockChain.

## 7. Error handling / adversarial behavior

Each failure mode has a named error and a test (see §8):
- Tampered amount/recipient/any signed felt → ECDSA verification fails → reject.
- Forged signature (attacker key) → commitment mismatch → reject (off-chain) / verify fails (in-VM).
- Replayed nonce → `nonce > last_nonce` guard fails.
- Expired intent → `current_block < expiry` guard fails.
- **Wrong account** → signature valid but for a different `account_id` → off-chain `pubkey↔accountId`
  check fails; in-VM verification against the active account's own key fails.

## 8. Testing

- **Golden vector tests** (Rust + TS): canonical felt ordering and Poseidon2 digest match byte-for-byte.
- **NEW end-to-end test: TS → Rust → MASM.** A TS-signed intent is transported, off-chain-verified by the
  Rust server, relayed, verified in-VM, and settles (P2ID note emitted, nonce advanced). This is the
  currently-missing link.
- **Adversarial suite:** tamper, forge, replay, expire, **wrong-account** (§7).
- **Assembly test:** the auth component assembles on the pinned 0.14 toolchain.

## 9. Tutorial rewrite

Restructured around the §2 flow, in the clearer MASM style the team proposed:
- named constant for the hashed-element count, `@locals(n)` with **documented** local slots,
- no "stash the values as a challenge" framing,
- digest extraction in a small named helper (`extract_digest_from_hashing_output`) rather than inline
  `squeeze`/`movdn` gymnastics,
- stack comments use lower-case field names, not capitalized non-words.

Security section: what exactly is signed, replay risk, message uniqueness (nonce + expiry + account binding),
recommended signing patterns, and common implementation mistakes.

## 10. Implementation risk & spike-first plan

Approach 2 places the signature check in the account's **auth** procedure. Note creation generally cannot
happen *inside* auth, so the realistic shape is: `execute_intent` (a regular account procedure) creates the
note from the verified felts, **bound to** the auth procedure that verifies the signature and gates it. That
binding-through-auth is the part with genuine feasibility risk on the 0.14 kernel.

**Therefore implementation step 1 is a narrow feasibility spike** proving a custom auth component can:
(a) assemble on 0.14;
(b) read the account's own key slot + the signature from advice and verify;
(c) bind to / gate the note creation (intent ⇄ output note).

**If a kernel restriction blocks any of these, implementation stops and the exact limitation is surfaced,
along with the Approach 1 fallback** (ECDSA key registered in the account; a single `execute_intent`
procedure verifies the intent against the account's own key and emits the note; permissive base auth). No
silent downgrade.

## 11. Out of scope (YAGNI)

- Real browser/WebClient wallet UI (the SDK signer is the canonical example; a browser mapping may be a
  short documented note only).
- A full swap engine / two-asset exchange (the comment's literal USDC→ETH); the P2ID note is the bounded,
  realistic action.
- Defining a production intent standard; this establishes a reproducible reference, not a standard.
