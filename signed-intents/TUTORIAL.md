# Signed Intents on Miden

A signed intent is a user's cryptographic authorization to perform an action — a transfer, an
order, a withdrawal — signed off-chain with their key and verified on-chain by an account
component written in MASM. The user signs once, the relayer (or any operator) submits the
transaction, and the Miden VM proves the signature is valid before committing any state change.
The critical security property is that **the account verifies the signature on-chain**: no
operator can forge, tamper with, or replay the intent because the cryptographic check runs
inside the transaction itself. Contrast this with off-chain verification — where the operator
checks the signature before broadcasting — which merely asks you to trust the operator not to
cheat. On-chain verification removes that trust entirely; an invalid signature makes the
transaction unprovable, full stop.

## What we'll cover

- The anatomy of a signed intent: a canonical felt vector with a domain-separation tag, a
  nonce replay guard, and a block-height expiry.
- ECDSA-K256-Keccak: the secp256k1 + Keccak256 signature scheme shared by Ethereum keys and
  Miden session keys.
- On-chain signature verification inside an account component written in MASM.
- Canonical message hashing with **Poseidon2** — the same algebraic hash used off-chain in
  TypeScript and reconstructed on-chain with the native `hperm` instruction.
- Replay protection via a strictly-increasing per-account nonce.
- Expiry protection via a block-height deadline.
- The relayer's role: assembling advice inputs (pubkey + signature) and submitting the transaction.
- Adversarial testing: four attacks and why each is cryptographically unprovable.

## Prerequisites

- Familiarity with Miden accounts and the account-component model. Read the
  [Counter recipe](https://0xpolygonmiden.github.io/miden-docs/developer-documentation/miden-client/cookbook/counter-account.html)
  and the account-component recipe before continuing.
- Basic MASM: the stack machine model, `call`/`exec`, and advice inputs.
- Rust (stable, 2021 edition) with `miden-protocol 0.14`, `miden-client 0.14`, and
  `miden-testing 0.14` in your `Cargo.toml`.
- Node.js with `@miden-sdk/miden-sdk 0.14` for the TypeScript signer.
- This example targets **miden-assembly 0.22.4** and **miden-core-lib 0.22.4**.

Clone the example:

```bash
git clone https://github.com/your-org/miden-perp
cd miden-perp/signed-intents
```

## Step 1 — Define the intent

The starting point is an explicit, canonical representation of the authorization the user is
signing. In `src/intent.rs` we define a six-field `Intent` struct and a deterministic function
that maps it to the exact sequence of field elements both TypeScript and MASM will hash.

### The canonical felt vector

```rust
// src/intent.rs

pub const DOMAIN_TRANSFER: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intent {
    pub recipient_prefix: u64,
    pub recipient_suffix: u64,
    pub amount: u64,
    pub nonce: u64,
    pub expiry_block: u64,
}

impl Intent {
    /// The exact field elements that are hashed to the signed Word.
    /// MUST match the TypeScript `intentFelts` ordering byte-for-byte.
    pub fn canonical_felts(&self) -> Vec<u64> {
        vec![
            DOMAIN_TRANSFER,
            self.recipient_prefix,
            self.recipient_suffix,
            self.amount,
            self.nonce,
            self.expiry_block,
        ]
    }

    /// The Word the user signs.
    pub fn message_word(&self) -> Word {
        message_word(&self.canonical_felts())
    }
}
```

Three design choices here are worth calling out:

**Domain tag.** `DOMAIN_TRANSFER = 1` occupies the first element. Its role is
domain-separation: a signature for a transfer intent cannot be replayed as a different action
type (cancel, withdraw, etc.) even if the remaining fields happen to collide. The perp repo
uses distinct tags for every action type.

**Nonce.** The `nonce` field is a per-account strictly-increasing counter. After each accepted
intent the on-chain authorizer records the nonce in storage; any future intent with a nonce
≤ the stored value is rejected. This is the replay guard.

**Expiry block.** `expiry_block` is an absolute chain block height. The on-chain verifier reads
`get_block_number` and rejects the intent if the chain has already reached or passed that
height. This caps how long a signature remains valid — important when a user wants to revoke
a pending order by simply waiting for the deadline.

### The hash: Poseidon2

`canonical_felts` is a vector of raw u64 values. Before the user can sign it, they need to
reduce it to a single 256-bit `Word`. That reduction uses **Poseidon2**, the protocol's
canonical algebraic hash function:

```rust
// src/intent.rs

pub fn message_word(felts: &[u64]) -> Word {
    let elements: Vec<Felt> = felts.iter().map(|&v| Felt::new(v)).collect();
    Poseidon2::hash_elements(&elements)
}
```

The reason Poseidon2 is non-negotiable: the Miden VM exposes the native `hperm` instruction,
which computes exactly the Poseidon2 permutation. The authorizer component will reconstruct the
hash on-chain using `hperm` (see Step 2). No other algebraic hash — RPO, Rescue, SHA-256 —
has a corresponding single-instruction VM primitive in this toolchain. Poseidon2 is the only
option that lets both sides agree on the hash without a general-purpose circuit.

> **Poseidon2 vs ECDSA — these are two different things.**
> Poseidon2 is the **hash** that squashes the 6-felt canonical vector into one 32-byte `Word`.
> ECDSA-K256-Keccak is the **signature** over that `Word`. You hash first, then sign the hash.
> MASM independently reconstructs the Poseidon2 hash from the intent felts and passes the result
> to `ecdsa_k256_keccak::verify`. The signature scheme never sees the raw felts.

## Step 2 — Verify it on-chain (MASM)

The authorizer is a single MASM procedure, `execute_intent`, compiled into an account
component. When the relayer submits a transaction, the transaction script calls this procedure
with the six intent felts on the operand stack and the signature in the advice provider.

### Inputs and outputs

```masm
# masm/authorizer.masm

#!   Operand inputs : [DOMAIN_TRANSFER, recipient_prefix, recipient_suffix,
#!                     amount, nonce, expiry_block, pad(10)]   (call pads to 16)
#!   Advice inputs  : [PK[9], SIG[17], ...]   (pushed by the relayer)
#!   Operand output : [pad(16)]               (all inputs consumed)

@locals(8)
pub proc execute_intent
```

The procedure is `call`-ed from the transaction script, so the stack is padded to depth 16 on
entry. The advice inputs (the 9 public-key felts and the 17 signature felts) are placed in the
advice provider by the relayer; they are invisible on the operand stack until the VM consumes
them.

### Phase 1 — Stash then reconstruct MSG with Poseidon2

The first challenge is that `hperm` is destructive: it consumes all 12 elements of the state.
Before hashing we stash the values we still need after (the record payload and the nonce) into
local memory:

```masm
# masm/authorizer.masm

    # --- 0. Sanity: domain tag must be DOMAIN_TRANSFER. ---
    dup
    push.DOMAIN_TRANSFER assert_eq.err=ERR_BAD_DOMAIN

    # Stash [r_pre, r_suf, amount, nonce] at local addr 0,
    # and [nonce, expiry, 0, 0] at local addr 4.
    dup.4 dup.4 dup.4 dup.4
    loc_storew_le.0 dropw
    dup.4 dup.6 push.0 push.0
    loc_storew_le.4 dropw

    # --- 1. Rebuild MSG = Poseidon2::hash_elements([DOMAIN, r_pre, r_suf, amount, nonce, expiry]) ---
    push.0 push.0
    movdn.7 movdn.7
    push.0 push.0 push.0 push.HASH_CAP_6
    movdnw.2
    hperm
    exec.squeeze_rate0
    # => [MSG(4), pad...]
```

`HASH_CAP_6 = 6` is the sponge capacity initializer for a 6-element input
(`6 % RATE_WIDTH(8) = 6`). The 12-element Poseidon2 sponge state is loaded onto the stack in
the order `[R0, R1, C]` from top to bottom, `hperm` runs one permutation, and `squeeze_rate0`
drops R1 and C to leave only the rate-0 word — the 4-element digest.

> **Toolchain note — `hperm` computes Poseidon2 in assembler 0.22.4, not RPO.**
> The miden-assembly source documents `hperm` as the "Poseidon2 permutation". Verified
> empirically: the `hperm` digest of the 6 sample felts equals `Rust Poseidon2::hash_elements`
> byte-for-byte. Do not assume `hperm` is RPO — it is not in this version.
> The advice Word is pulled with `padw adv_loadw` in this toolchain (not `adv_pushw`).

### Phase 2 — Load the owner commitment and verify the signature

```masm
# masm/authorizer.masm

    # --- 2. Load committed pubkey from storage and verify the signature. ---
    push.OWNER_PK_SLOT[0..2] exec.active_account::get_item
    # => [PK_COMM, MSG, pad...]
    exec.ecdsa_k256_keccak::verify
    # => [pad...]   (aborts the tx if commitment or signature is invalid)
```

`OWNER_PK_SLOT` is the named storage slot set at account creation (see Step 4). The
`get_item` call reads it from the account's own storage — **not from the caller**. This is the
security boundary: the relayer cannot substitute a different key, because the commitment is
fixed on-chain when the account is deployed. `ecdsa_k256_keccak::verify` reads `PK[9]` and
`SIG[17]` from the advice provider and aborts the transaction if either the commitment check
or the signature check fails.

### Phase 3 — Replay and expiry guards, then record

```masm
# masm/authorizer.masm

    # --- 3. Replay guard: intent nonce must exceed the stored last_nonce. ---
    padw loc_loadw_le.4
    drop drop drop
    # => [nonce, pad...]
    push.LAST_NONCE_SLOT[0..2] exec.active_account::get_item
    drop drop drop
    # => [nonce_stored, nonce_intent, pad...]
    u32assert2.err=ERR_STALE_NONCE
    u32gt assert.err=ERR_STALE_NONCE

    # Write the new nonce back.
    padw loc_loadw_le.4
    drop drop drop
    push.0 push.0 push.0
    push.LAST_NONCE_SLOT[0..2] exec.native_account::set_item
    dropw

    # --- 4. Expiry: current block height must be < expiry_block. ---
    exec.tx::get_block_number
    padw loc_loadw_le.4
    drop drop
    swap drop
    # => [expiry, block_num, pad...]
    swap
    # => [block_num, expiry, pad...]
    u32assert2.err=ERR_EXPIRED
    u32gt assert.err=ERR_EXPIRED

    # --- 5. Record authorized payload to slot "last_authorized". ---
    padw loc_loadw_le.0
    push.LAST_AUTH_SLOT[0..2] exec.native_account::set_item
    dropw

    exec.sys::truncate_stack
end
```

After the signature check the nonce guard uses `u32gt` to assert `nonce_intent > nonce_stored`.
The expiry guard does the same — `block_num < expiry_block` — using `get_block_number` from
the transaction context. Both errors produce named string messages (`ERR_STALE_NONCE`,
`ERR_EXPIRED`) that surface in test output when an adversarial test triggers them. The record
step writes `[r_pre, r_suf, amount, nonce]` to storage slot `last_authorized` so that the
relayer (or any off-chain reader) can confirm the intent settled on-chain.

### Named storage slots

```masm
# masm/authorizer.masm

const OWNER_PK_SLOT   = word("signed_intents::authorizer::owner_pubkey_commitment")
const LAST_NONCE_SLOT = word("signed_intents::authorizer::last_nonce")
const LAST_AUTH_SLOT  = word("signed_intents::authorizer::last_authorized")
```

Named slots let the assembler derive the storage address from a human-readable string without
requiring you to hardcode numeric slot indices. The same string constants are mirrored in
`src/relayer.rs` so Rust can read the same slots after a transaction.

## Step 3 — Sign the intent (TypeScript)

The TypeScript signer lives in `ts/signIntent.ts`. Its job is to reproduce the exact same
canonical felts and Poseidon2 hash as the Rust side, then produce an ECDSA-K256-Keccak
signature over the resulting `Word`.

### Canonical felts — mirroring Rust

```typescript
// ts/signIntent.ts

const DOMAIN_TRANSFER = 1n;

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
```

The element order is identical to `Intent::canonical_felts`. Both sides use the same six-felt
layout; any difference would produce a different hash and a signature that the authorizer
rejects.

### Hashing with Poseidon2

```typescript
// ts/signIntent.ts

export function messageWord(felts: bigint[]): Word {
  const elements = felts.map((v) => new Felt(v));
  return Poseidon2.hashElements(new FeltArray(elements));
}
```

`Poseidon2.hashElements` from `@miden-sdk/miden-sdk` computes the same algebraic hash as
Rust's `Poseidon2::hash_elements`. This is verified by a golden-vector test: both sides hash
the sample intent and compare the resulting hex strings byte-for-byte.

### Signing

```typescript
// ts/signIntent.ts

export function signIntent(key: AuthSecretKey, i: IntentInput): SignResult {
  const word = messageWord(intentFelts(i));
  const signature: Signature = key.sign(word);
  return {
    signatureHex: bytesToHex(signature.serialize()),
    publicKeyHex: bytesToHex(key.publicKey().serialize()),
    messageWordHex: wordToHex(word),
  };
}
```

`AuthSecretKey.ecdsaWithRNG()` generates an ECDSA-K256-Keccak key — the same scheme used for
Ethereum keys and for Miden session keys in the perp repo. `key.sign(word)` produces a
deterministic signature given the key material; the `Signature` object is serialized to bytes
and hex-encoded for hand-off to the Rust relayer.

> **Gotcha — `Word.toHex()` is not the same as Rust `Word::as_bytes()`.**
> The TS SDK's `Word.toHex()` uses a different byte ordering than Rust's `as_bytes()`, so
> pasting the two hex strings side-by-side will NOT match. To get matching hex across
> languages, use `Word.toU64s()` and serialize each element as little-endian 8 bytes —
> exactly what `wordToHex` in the signer does. The underlying `Word` *values* agree; this is
> only a serialization convention mismatch, not a hash disagreement.

```typescript
// ts/signIntent.ts

export function wordToHex(word: Word): string {
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
```

## Step 4 — Relay and settle (Rust)

The relayer has two responsibilities: deploy the authorizer account (once, at setup time) and
relay each signed intent (once per user action). Both functions live in `src/relayer.rs`.

### Deploying the authorizer

```rust
// src/relayer.rs

pub fn deploy_authorizer(chain: &mut MockChain, owner: &PublicKey) -> DeployedAuthorizer {
    let library = CodeBuilder::default()
        .compile_component_code("signed_intents::authorizer", AUTHORIZER_MASM)
        .expect("authorizer.masm must assemble");

    let owner_slot = StorageSlotName::new(OWNER_PK_SLOT).expect("slot name must parse");
    let nonce_slot = StorageSlotName::new(LAST_NONCE_SLOT).expect("slot name must parse");
    let auth_slot = StorageSlotName::new(LAST_AUTH_SLOT).expect("slot name must parse");

    let pk_comm_word: Word = owner.to_commitment().into();

    let component = AccountComponent::new(
        library,
        vec![
            StorageSlot::with_value(owner_slot, pk_comm_word),
            StorageSlot::with_value(nonce_slot, Word::from([0u32, 0, 0, 0])),
            StorageSlot::with_value(auth_slot, Word::from([0u32, 0, 0, 0])),
        ],
        AccountComponentMetadata::mock("signed_intents::authorizer"),
    )
    .expect("authorizer component must build");

    // ...
    let account = {
        let (auth_component, _authenticator) = Auth::IncrNonce.build_component();
        AccountBuilder::new(rand::random())
            .storage_mode(AccountStorageMode::Public)
            .with_auth_component(auth_component)
            .with_component(component)
            .build_existing()
            .expect("authorizer account must build")
    };
    // ...
}
```

The owner commitment (`owner.to_commitment()`) is stored in storage slot 0 at account
creation. This is the single moment the key material is bound to the account; from this point
on, every intent relay is verified against this stored commitment — never against a key
supplied by the caller.

The account uses `Auth::IncrNonce` as its protocol-level auth component. This is a mock auth
that simply increments the account nonce to give each transaction a state delta (the kernel
rejects transactions with no state change). `Auth::IncrNonce` does **not** verify any
signature at the protocol level; `execute_intent` is the sole authorization boundary.

### Relaying an intent

```rust
// src/relayer.rs

pub fn relay_intent(
    chain: &mut MockChain,
    deployed: &DeployedAuthorizer,
    intent: &Intent,
    signature_hex: &str,
) -> Result<(), RelayError> {
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| RelayError::Rejected(format!("bad signature hex: {e}")))?;
    let signature = Signature::read_from_bytes(&sig_bytes)
        .map_err(|e| RelayError::Rejected(format!("cannot deserialise signature: {e}")))?;

    let msg = intent.message_word();

    // Guard against a panic from ECDSA recovery inside `to_prepared_signature`.
    let prepared: Vec<Felt> = {
        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(|| signature.to_prepared_signature(msg));
        panic::set_hook(prev_hook);
        result.map_err(|e| { /* ... */ RelayError::Rejected(/* ... */) })?
    };

    // ...
    let advice_inputs = AdviceInputs::default().with_stack(prepared);
    // ...
}
```

`Signature::to_prepared_signature(msg)` does the ECDSA public-key recovery step in Rust —
it recovers the signer's public key from the signature and message, then encodes both as
`Vec<Felt>` (9 felts for the pubkey, 17 for the signature). These felts become the advice
stack that the MASM procedure reads with `ecdsa_k256_keccak::verify`.

The `catch_unwind` wrapper is needed because `to_prepared_signature` panics (rather than
returning `Err`) when ECDSA recovery fails on a tampered intent. Both a panic and a VM
execution error map to `RelayError::Rejected`, giving callers a clean, uniform error type.

The transaction script is assembled inline:

```rust
// src/relayer.rs

    let tx_script_code = format!(
        r#"
        use signed_intents::authorizer->authorizer
        use miden::core::sys

        begin
            push.{expiry}.{nonce}.{amount}.{r_suf}.{r_pre}.{domain}
            call.authorizer::execute_intent
            exec.sys::truncate_stack
        end
        "#,
        domain = felts[0],
        r_pre = felts[1],
        r_suf = felts[2],
        amount = felts[3],
        nonce = felts[4],
        expiry = felts[5],
    );
```

After execution the transaction is committed with `add_pending_executed_transaction` +
`prove_next_block` so that subsequent `read_last_nonce` / `read_last_authorized` calls see
the updated storage.

## Step 5 — Break it on purpose

The best way to understand what "on-chain verification" really buys you is to try to cheat
and watch it fail. `tests/adversarial.rs` runs four attacks, each of which the authorizer
rejects as cryptographically unprovable.

### Attack 1 — Tampered amount

```rust
// tests/adversarial.rs

#[test]
fn relayer_cannot_tamper_with_the_amount() {
    let k = key();
    let signed = make_intent(1, 100_000);
    let sig_hex = sign(&k, &signed);

    let mut chain = new_chain();
    let dep = deploy_authorizer(&mut chain, &k.public_key());

    // Relayer submits a DIFFERENT amount than was signed.
    let mut tampered = signed;
    tampered.amount = 9_999_999;

    let r = relay_intent(&mut chain, &dep, &tampered, &sig_hex);
    assert!(matches!(r, Err(RelayError::Rejected(_))), /* ... */);
}
```

When the relayer inflates `amount` from 1000 to 9,999,999, the on-chain Poseidon2
reconstruction hashes the tampered felts into a *different* MSG. The signature was created
over the original MSG; ECDSA recovery on the tampered MSG either panics (caught and mapped to
`Rejected`) or recovers a pubkey that does not match the owner commitment in storage, causing
the on-chain commitment guard to abort the transaction. The proof is impossible to generate.

### Attack 2 — Forged signature

```rust
// tests/adversarial.rs

#[test]
fn a_forged_signature_is_rejected() {
    let owner = key();
    let attacker = key();
    let i = make_intent(1, 100_000);

    let attacker_sig_hex = sign(&attacker, &i);

    let mut chain = new_chain();
    let dep = deploy_authorizer(&mut chain, &owner.public_key());

    let r = relay_intent(&mut chain, &dep, &i, &attacker_sig_hex);
    assert!(matches!(r, Err(RelayError::Rejected(_))), /* ... */);
}
```

The attacker signs a valid intent with their own key. The account was deployed with the
*owner's* commitment in storage slot 0. ECDSA recovery succeeds — it recovers the *attacker's*
pubkey — but that pubkey does not match the owner's commitment. The commitment guard aborts.

### Attack 3 — Replayed nonce

```rust
// tests/adversarial.rs

#[test]
fn a_replayed_nonce_is_rejected() {
    let k = key();
    let mut chain = new_chain();
    let dep = deploy_authorizer(&mut chain, &k.public_key());

    let first = make_intent(1, 100_000);
    let sig1 = sign(&k, &first);

    // First relay must succeed — proves the rejection in round 2 is due to replay, not setup.
    relay_intent(&mut chain, &dep, &first, &sig1).expect("first relay must settle");

    // Replay the same nonce.
    let r = relay_intent(&mut chain, &dep, &first, &sig1);
    assert!(matches!(r, Err(RelayError::Rejected(_))), /* ... */);
}
```

The first relay settles, advancing `last_nonce` to 1 in storage. The second relay submits the
identical intent (nonce = 1). The on-chain check `nonce_intent > nonce_stored` evaluates to
`1 > 1 = false`, so `assert.err=ERR_STALE_NONCE` aborts the transaction.

Note that the test explicitly asserts the *first* relay succeeds. This is deliberate: it
proves the rejection in the second round is caused by the replay guard, not by some setup bug.

### Attack 4 — Expired intent

```rust
// tests/adversarial.rs

#[test]
fn an_expired_intent_is_rejected() {
    let k = key();
    let mut chain = new_chain();
    let dep = deploy_authorizer(&mut chain, &k.public_key());

    let i = make_intent(1, 1);
    let sig = sign(&k, &i);

    advance_blocks(&mut chain, 5);

    let r = relay_intent(&mut chain, &dep, &i, &sig);
    assert!(matches!(r, Err(RelayError::Rejected(_))), /* ... */);
}
```

The intent is signed with `expiry_block = 1`. After deploying the authorizer the chain is at
block 1 (genesis = 0, builder adds one block). `advance_blocks` produces 5 empty blocks,
bringing the chain to block 6. The on-chain check `block_num < expiry_block` evaluates to
`6 < 1 = false`, so `assert.err=ERR_EXPIRED` aborts the transaction.

### The real lesson from adversarial testing

Writing these four tests caught a genuine replay bug that the happy-path test had masked.
The nonce guard in an earlier iteration read storage slot 1 (`last_nonce`) but inadvertently
loaded the wrong element of the returned word, so a replayed nonce compared against 0 and
always passed. The happy-path test never triggered this because a nonce of 1 is always greater
than 0; only the replay test — which relies on a *second* relay being rejected *after* the
nonce advances — surfaced the bug.

**"All happy-path tests pass" is not the same as "the security property holds."** Adversarial
tests are not optional extras; they are the specification of what the authorizer is actually
supposed to prevent.

## Running the example

### Rust tests (12 tests total)

```bash
cd signed-intents
cargo test
```

Expected output:

```
running 4 tests  # adversarial.rs
test relayer_cannot_tamper_with_the_amount ... ok
test a_forged_signature_is_rejected ... ok
test a_replayed_nonce_is_rejected ... ok
test an_expired_intent_is_rejected ... ok

running 3 tests  # authorizer.rs
test authorizer_assembles ... ok
test verify_as_oracle_negative_hits_the_commitment_guard ... ok
test verify_as_oracle_accepts_a_valid_intent ... ok

running 2 tests  # golden.rs
test canonical_felts_are_in_the_agreed_order ... ok
test message_word_matches_the_golden_vector ... ok

running 1 test   # happy_path.rs
test valid_intent_is_authorized_and_recorded ... ok

running 2 tests  # spike.rs
test on_chain_ecdsa_verify_rejects_a_tampered_message ... ok
test on_chain_ecdsa_verify_accepts_a_valid_signature ... ok
```

### TypeScript tests and demo (3 tests)

```bash
cd signed-intents/ts
npm test
```

To run the signing demo (prints a JSON blob with the signed intent, signature hex, and pubkey
hex):

```bash
npm run demo
```

## Continue learning

**The perp repo** (`miden-perp/`) shows the other side of the trust trade-off: the perpetuals
exchange uses *off-chain* operator verification for session-key intents. The operator checks
signatures before broadcasting, which is faster and cheaper (no on-chain ECDSA circuit) but
requires users to trust the operator not to censor or misreport fills. Neither approach is
universally better — the right choice depends on whether censorship resistance or throughput
matters more for your application.

**miden-x402** demonstrates a Falcon512 voucher verified *inside a note* rather than an
account. The message is still hashed with Poseidon2 (same family as this example) but the
container is a note, not an account component, and the signature scheme is Falcon512 — the
protocol's native, lattice-based scheme. Falcon512 is the cheaper alternative when
EVM-key compatibility is not required: it has a smaller proof footprint and does not need the
secp256k1 + Keccak256 circuit. If you don't need your Miden keys to correspond to Ethereum
keys, prefer Falcon512.
