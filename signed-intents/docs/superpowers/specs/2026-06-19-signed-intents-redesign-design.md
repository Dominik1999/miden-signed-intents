# Signed Intents on Miden — Redesign Design Spec

**Date:** 2026-06-19 (rev. 2026-06-21: two-account operator-custody model)
**Status:** Approved (design); implementation pending spike (see §11)
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
- The MASM verifier reads a public-key commitment from a **custom storage slot** the deployer hardcoded
  at deploy time; the key is **not** associated with any account owner and authorizes nothing.
- The account uses `Auth::IncrNonce` — a **mock** auth component — so all "authorization" is bolted on
  beside the real (absent) auth boundary.

Secondary problems: TypeScript test/build fragility, no end-to-end test linking the TS signer to MASM
verification, and tutorial prose that is convoluted and reads as LLM-generated.

## 2. Requirements (issue #314 + team thread)

The deliverable must demonstrate, executably and without protocol-level hand-holding:

1. Canonical message construction, **explicit** serialization, hashing, and the exact intermediate values.
2. Signature generation in the **frontend/wallet** and verification in both the **Rust client** and
   **inside the VM (MASM)**.
3. **A way to verify that a public key really belongs to a specific Miden account** — verified in both
   Rust and MASM, *before* execution so a doomed transaction is never submitted. *(mico, issue thread.)*
   See §5 for how this is actually achievable on Miden.
4. Handling invalid signatures; using a successful verification to **authorize a real action** (move funds).
5. Security discussion: what is signed, replay risk, message uniqueness, recommended patterns, common mistakes.

## 3. The model: operator custody with key registered at deposit

The realistic, Miden-correct shape of "user signs an intent, an operator executes it" is **two accounts
and a deposit**:

- **User Account** — its **native authentication is the `ecdsa_k256_keccak` key**. One key controls the
  account *and* signs intents.
- **Operator Account** — custodies deposited funds, and in its storage tracks, per depositor:
  the registered ECDSA pubkey, the balance, and the last-used nonce. Its MASM is the intent verifier.

### Why a deposit, and why the key is registered there (the crux)

A Miden `AccountID` **does not expose the account's auth pubkey**, and an account is not obligated to
reveal it. Therefore an operator **cannot**, given only a user's account ID, look up or derive the user's
pubkey, nor cryptographically check "does this supplied pubkey belong to that account ID?" at intent time.

The binding must instead be **captured at a moment the protocol authenticates** — the deposit:

> When the User Account performs the deposit transaction, that transaction is authorized by the User
> Account's **native ECDSA auth**. Registering the pubkey as part of that authenticated action means the
> operator records a key that **provably controls the user account** — because only that key could have
> authorized the deposit. The binding is established once, at registration, by native auth — not
> re-derived later from the account ID (which is impossible).

This is the precise, honest answer to mico's requirement: *"belongs to the account"* is enforced at
deposit by native auth, **not** as a per-intent account-ID lookup. It is exactly how a custodial operator
or a payment-channel deposit works, and it is the distinction from the rejected original (a key hardcoded
at deploy, tied to no owner): here the key is registered **per-user, at runtime, via an authenticated
action, against real deposited funds**.

## 4. Canonical message format & serialization

Intent fields, **fixed order** (normative; mirrored byte-for-byte in Rust and TS):

```
index  field                type    notes
0      DOMAIN_TRANSFER      felt    domain separation tag (constant)
1      user_id_prefix       felt    depositor's User Account ID, high word
2      user_id_suffix       felt    depositor's User Account ID, low word
3      recipient_prefix     felt    payout recipient account ID, high word
4      recipient_suffix     felt    payout recipient account ID, low word
5      faucet_id            felt    asset faucet ID
6      amount               felt    asset amount to move out of the deposit
7      nonce                felt    strictly increasing per depositor
8      expiry               felt    block height; intent invalid at/after this block
```

- **Encoding:** Miden field elements (`Felt`, u64 in the Goldilocks field). No floats, no variable-length encoding.
- **Array handling:** fixed-length array of 9 felts; no dynamic arrays at the serialization boundary.
- **`user_id` is a signed field** (indices 1–2): the intent is bound to one depositor, and the operator can
  index its per-depositor storage by it. The recipient (3–4) is a Miden account ID; the actual P2ID
  RECIPIENT digest is derived inside the contract from these felts.
- **Serialization boundary:** the 9-felt vector is the canonical signable object. Transport wraps it as
  `{ intent, signatureHex, publicKeyHex, userAccountId }`; those wrapper fields are **not** re-hashed.

A **golden vector** (the exact 9 felts and the resulting digest hex) is published and asserted by tests on
both sides, so cross-language agreement is proven, not assumed.

## 5. Where the operator's knowledge of the pubkey comes from

- **It is NOT** read from the user's account ID (impossible — §3).
- **It IS** the value registered in the Operator Account's storage at deposit, keyed by `user_id`.
- The user-supplied `publicKeyHex` in transport is at most a convenience; correctness comes from comparing
  against the **registered** key. The operator authorizes movement of funds based on signatures by the key
  it recorded at deposit.

Because the registered key is the User Account's native auth key (§3), "the operator moves the user's
funds on a signed intent" is equivalent to "the account owner authorized moving their funds."

## 6. End-to-end flow

**Phase A — Deposit (on-chain, authenticated by the user's ECDSA key)**
1. User Account runs a tx, authorized by its **native ECDSA auth**, that (a) transfers funds to the
   Operator Account and (b) registers its ECDSA pubkey + opens a tracked balance in operator storage,
   keyed by `user_id`.

**Phase B — Intent (off-chain, just a signature)**
2. User builds the 9-felt intent (§4), hashes it `MSG = Poseidon2::hash(intent)`, and **signs `MSG`** with
   the same ECDSA key. Sends `{ intent, signature, publicKey, userAccountId }` to the operator.

**Phase C — Off-chain pre-check (operator, Rust) — fail fast before gas**
3. Operator verifies the signature over `MSG` against the **registered** pubkey for `user_id`, and
   sanity-checks the intent (nonce > stored, not expired, amount ≤ balance). Reject without submitting on
   any failure.

**Phase D — Settlement (on-chain, in the Operator Account's MASM)**
4. Operator submits a tx **on its own account** pushing the 9 intent felts and injecting the signature into
   advice. The Operator Account's code: rebuilds `MSG`; loads the **registered** pubkey for `user_id` from
   its own storage; `ecdsa_k256_keccak::verify`; enforces `nonce > last_nonce` and `block < expiry`;
   **debits the tracked balance**; emits the payout P2ID note (derived from the verified felts); writes back
   `last_nonce`.

## 7. Who signs / verifies what (final)

- **User signs:** the deposit tx (native ECDSA auth) **and** each off-chain intent — same key both times.
- **Operator verifies (Rust, off-chain):** the intent signature against the pubkey it holds from deposit —
  to fail fast.
- **Operator Account verifies (MASM, on-chain):** the same signature against the pubkey in **its own**
  storage, then moves the funds. This is the authorization boundary; the relayer/operator is trusted with
  nothing — altering any signed felt breaks verification.

## 8. Components

| Component | File | Responsibility |
|---|---|---|
| User Account (ECDSA native auth) | `src/…` | Built with `Auth::BasicAuth { EcdsaK256Keccak }`; authorizes the deposit; owns the signing key. |
| Operator Account + verifier MASM | `masm/operator.masm`, `src/…` | Per-depositor storage (pubkey, balance, nonce); deposit handler; intent verifier + payout. |
| TS "wallet" signer | `ts/signIntent.ts` | Build 9-felt intent → Poseidon2 → `AuthSecretKey(EcdsaK256Keccak).sign()`; emit `{ signature, publicKey, userAccountId }`. |
| Rust operator/relayer | `src/relayer.rs` | Off-chain pre-check (§6 Phase C); assemble + submit the settlement tx. |

### MASM verifier (operator account), in the clearer style (§10)
1. Rebuild `MSG = Poseidon2::hash(intent_felts)`.
2. Load the registered pubkey for `user_id` from operator storage.
3. `ecdsa_k256_keccak::verify` of `MSG` against that key.
4. Replay guard `nonce > last_nonce`; expiry guard `block < expiry`.
5. Debit tracked balance for `user_id` by `amount`; emit P2ID note derived from the verified felts.
6. Persist `last_nonce`.

## 9. Error handling / adversarial behavior

Each failure mode gets a named error and a test (§10):
- Tampered amount/recipient/any signed felt → ECDSA verify fails.
- Forged signature (attacker key) → not equal to registered key → verify fails (and off-chain pre-check rejects).
- Replayed nonce → `nonce > last_nonce` fails.
- Expired intent → `block < expiry` fails.
- **Wrong depositor** → intent signed by a key not registered for that `user_id` → verify fails.
- **Over-withdrawal** → `amount > tracked balance` → debit underflow guard fails.

## 10. Testing

- **Golden vector tests** (Rust + TS): canonical felt ordering and Poseidon2 digest match byte-for-byte.
- **NEW end-to-end test: TS → Rust → MASM.** A TS-signed intent is transported, off-chain-verified by the
  Rust operator, settled on-chain (balance debited, payout note emitted, nonce advanced). The currently
  missing link.
- **Registration setup test:** operator storage holds the depositor's pubkey/balance/nonce (registration
  modeled simply per §11); the verifier reads it correctly.
- **Adversarial suite:** tamper, forge, replay, expire, wrong-depositor, over-withdrawal (§9).
- **Assembly test:** operator component assembles on the pinned 0.14 toolchain.

## 11. Scope priority & implementation risk

**The core showcase is Phase D: the Operator Account verifying a user-signed intent in MASM** — load the
registered pubkey for `user_id` from operator storage, `ecdsa_k256_keccak::verify` the signed intent,
enforce nonce/expiry, and emit the payout. This is the one thing that must work and is the heart of the
tutorial. The implementation plan's **first step is a narrow spike that proves exactly this** on the pinned
0.14 toolchain:

> (a) build an Operator Account whose storage holds a per-depositor pubkey; (b) read it in MASM; (c)
> `ecdsa_k256_keccak::verify` a TS/Rust-produced intent signature against it; (d) emit the payout note from
> the verified felts. **If a kernel restriction blocks any step, implementation stops and the exact
> limitation is surfaced with options — no silent downgrade.**

### Registration is modeled simply (not a cryptographic showcase)
The pubkey reaches operator storage via the deposit, but the tutorial does **not** need to *cryptographically
prove* the registration binding inside the VM. Default: **trusted registration** — the operator records
`(user_id, pubkey)` from the user-authorized deposit, and the tutorial states plainly that the binding rests
on the deposit having been authorized by the user's own ECDSA key (§3). The conceptual binding argument of §3
still holds; we simply don't implement an in-VM registration proof.

Deposit-time *cryptographic* registration (operator verifies an ECDSA signature during the deposit-handling
tx, or binds the key into the deposit note) is recorded here as a **possible later extension**, explicitly
out of scope for the first version per the team's steer that the main showcase is intent verification.

## 12. Out of scope (YAGNI)

- Real browser/WebClient wallet UI (the SDK signer is the canonical example; a browser mapping may be a
  short documented note only).
- A full swap engine / two-asset exchange (the comment's literal USDC→ETH); the payout P2ID note is the
  bounded, realistic action.
- Defining a production intent standard; this establishes a reproducible reference, not a standard.
- Withdrawal-back-to-user flows, partial-fill accounting beyond a single balance debit, multi-asset deposits.
