# Sovereign Privacy: Client Implementation Status

This document describes the status of the one privacy client target defined by
[`shape.md`](shape.md), which is the canonical alignment document. There are no
phases, stages, slices, or separate delivery tracks: the required privacy
guarantees are either wired into the real client paths (working out of the box on
the privacy network profile and covered by tests) or described plainly as
incomplete. The roadmap *"Ethereum Privacy: The Road to Self-Sovereignty"* is the
source of scope; its phase labels are source-context only.

The client target comprises the required privacy guarantees:

- **Confidential ETH** — consensus-level shielded transfers (built on the merged
  Pedersen commitments, EIP-5564 stealth addresses, shielded-pool primitives, and
  privacy precompiles).
- **Network-origin privacy** — Dandelion++, wired into live transaction propagation.
- **Opinionated privacy defaults** — privacy active by default on the privacy
  network profile, not behind user opt-in flags.
- **Encrypted mempool** — threshold/IBE-based, with a keyper committee and
  decrypt-at-inclusion through the real block path.

All consensus-affecting behavior is gated behind the Privacy1 fork so mainnet
semantics never change until activation. Generalising privacy to tokens, arbitrary
computation, and post-quantum cryptography is **future roadmap beyond this client
target**, recorded at the end of this document as context, not as deferred work of
the current client.

---

## Confidential ETH transactions (consensus-level)

**Goal.** Users can shield native ETH into a protocol-managed pool, transfer it
confidentially (hidden sender, recipient, amount), and unshield back — verified by
the client as a consensus rule.

### Workstreams

1. **New EIP-2718 transaction type — `ShieldedTxType = 0x05`.**
   - Add to `core/types/`: a new `ShieldedTx` implementing the `TxData` interface
     (`core/types/transaction.go:76`). Fields: anchor (Merkle root), input
     nullifiers, output note commitments, encrypted note ciphertexts, a binding
     ZK proof, and a public `valueBalance` (positive = unshield, negative = shield).
   - Wire it through `Transaction` marshaling, `Signer` (`core/types/transaction_signing.go`),
     receipt handling (`core/types/receipt.go:208`), and the RLP/JSON codecs.
   - Risk: every `switch tx.Type()` in the tree must learn the new type. Grep
     `BlobTxType`/`SetCodeTxType` for the full inventory of call sites.

2. **Protocol-native shielded pool state.**
   - Promote the in-memory `core/privacy.IncrementalMerkleTree` + `NullifierSet`
     into state-backed structures at a reserved system address, persisted via the
     state trie. Note-commitment tree root(s) become part of consensus state.
   - Double-spend prevention = nullifier presence check against state, mirroring
     Tornado/Zcash (Roadmap Ph.4 §1).

3. **ZK verification.**
   - Add the `gnark` proving/verifying frontend as a dependency (only
     `gnark-crypto` is present today) and a **PlonK verifier precompile**
     (`0x14`) plus range-proof support, fulfilling Roadmap Ph.3 §3 ("precompiles
     for verifying common zk-SNARK schemes").
   - The shielded transfer circuit proves: input notes exist in the tree (Merkle
     membership), nullifiers are correctly derived, output commitments are
     well-formed, and `Σ inputs = Σ outputs + valueBalance` (reuse the Pedersen
     homomorphism / `PEDERSEN_ADD`).
   - Circuits live in `core/privacy/circuit/` with a checked-in
     verifying key; proving stays client-side/wallet-side.

4. **State-transition & pool integration.**
   - `core/state_transition.go` `execute()` (`:602`) / `preCheck()` (`:494`):
     validate the proof, consume nullifiers, append commitments, settle
     `valueBalance` against the EVM balance for shield/unshield.
   - `core/txpool/validation.go` `ValidateTransaction` (`:62`): stateless proof &
     structural checks; `ValidateTransactionWithState` (`:261`): anchor freshness
     and nullifier non-membership. Mempool replacement rules keyed by nullifier set.

5. **Fork gating + RPC.**
   - Add an `IsPrivacy1` fork to `params.Rules` (`params/config.go:1377`), gating
     the tx type and precompile.
   - Extend the `privacy` RPC namespace: `shield`, `unshield`, `transfer`,
     `scanNotes` (using existing stealth scanning), `getMerkleProof`.

6. **Network-origin privacy — Dandelion++ (Roadmap Ph.1 §3). _Wired; multi-hop, default-on, hardened._**
   - The Dandelion++ router ([`p2p/dandelion/dandelion.go`](p2p/dandelion/dandelion.go))
     is wired into the live transaction-propagation path
     ([`eth/handler_dandelion.go`](eth/handler_dandelion.go)) as a multi-hop stem
     over the dedicated `dle` sub-protocol
     ([`eth/protocols/dandelion`](eth/protocols/dandelion)). The originator never
     diffuses by chance; local-origin status persists across re-broadcasts and
     such transactions are withheld from initial mempool sync until they fluff;
     multiple epoch-stable successors are used; honest relays continue the stem
     and each arms its own embargo; inbound gossip cancels embargoes; and an
     embargo loop is the black-hole failsafe.
   - Stem-successor selection is hardened against eclipse / connection-reset
     attacks ([`eth/handler_dandelion_eclipse.go`](eth/handler_dandelion_eclipse.go)):
     stability gating, subnet diversity, outbound preference, and churn monitoring
     with suspected-eclipse metrics.
   - Per the Opinionated Privacy Defaults in `shape.md`, it is **active by default
     on the privacy network profile** (any network that activates the Privacy1
     fork) and is not a user opt-in. The only disable path is the labelled
     emergency/diagnostic override `--dandelion.disable`; `--dandelion.stemprob`,
     `--dandelion.epoch`, `--dandelion.embargo`, and `--dandelion.embargojitter`
     are diagnostic/devnet tuning only. No consensus rules change. Covered by
     router unit tests and multi-node origin-obfuscation, multi-hop, relay-embargo,
     re-broadcast-persistence, diffusion, eclipse-hardening, and churn tests in
     [`eth/handler_dandelion_test.go`](eth/handler_dandelion_test.go).

### Exit criterion
A devnet where `privacy_transfer` moves shielded ETH between two parties such that
the public trace reveals neither amount nor the sender↔recipient link, validated by
a full sync of a third node. Unit + state tests green; `go test ./core/...`.

### Key decisions
- **Proof system: PlonK (BN254), via gnark.** ✅ *Decided.* PlonK uses a universal,
  updatable trusted setup (one SRS shared by every circuit) instead of a fresh
  per-circuit ceremony, so new privacy circuits can ship without a new ceremony.
  gnark provides a production Go implementation (Halo2 is Rust-only, which would
  force an FFI/sidecar boundary). Migration to a transparent STARK verifier is
  deferred to future roadmap (post-quantum).
- **Pool model**: single ETH pool vs multi-asset (defer multi-asset to future roadmap).

### Status

| Workstream | State |
| --- | --- |
| 3. ZK verification — PlonK BN254 verifier + `PLONK_VERIFY` precompile (`0x14`) | ✅ **Done** — `core/privacy/zk`, `core/vm/contracts_privacy.go`; full prove→verify test coverage |
| 1. `ShieldedTxType` (`0x05`) transaction — TxData, RLP, signing, receipts, JSON-RPC | ✅ **Done** — `core/types/tx_shielded.go` |
| 2. State-backed shielded pool — incremental Merkle tree + nullifier set + recent-roots ring + VK registry, all in the state trie | ✅ **Done** — `core/privacy/pool` |
| 4. Fork gating — `Privacy1Time` / `ChainConfig.IsPrivacy1` / `Rules.IsPrivacy1` | ✅ **Done** — `params/config.go` |
| 1+2+4 integration — state-transition settlement (`settleShielded`) and txpool gating | ✅ **Done** — `core/state_transition.go`, `core/txpool/validation.go`; end-to-end shield→unshield→double-spend test |
| 5. Production shielded-transfer circuit — 2-in/2-out MiMC circuit enforcing Merkle membership, nullifier derivation, commitment well-formedness, value conservation and range checks; native prover + wallet helpers | ✅ **Done** — `core/privacy/circuit`; soundness tests reject value inflation, forged nullifiers/commitments and non-member spends |
| Devnet wiring — deterministic devnet keys, genesis VK install, `geth --dev.privacy`, RPC | ✅ **Done** — `core.EnablePrivacyDevnet`, `pool.GenesisStorage`, `--dev.privacy`, `privacy_poolInfo`/`privacy_buildShield`; full block-processing integration test |
| 5. Trusted-setup **ceremony** (real multi-party SRS) | ⏳ **Required before any value-bearing network** — the devnet SRS is deterministic but insecure (public seed), loudly labelled in `circuit.DevnetSetup` |
| 5. Wallet note-scanning / spend-side RPC (membership requires a wallet note DB) | ⏳ Next |

### Devnet operation

`geth --dev --dev.privacy` brings up a developer chain with Privacy1 active
from genesis and the shielded-transfer verifying key installed in the pool's
genesis state. Wallets/tooling use:

- `privacy_poolInfo` → current anchor (root) and leaf count;
- `privacy_buildShield` → an unsigned, proven shield transaction plus the created
  note's secret (the caller signs with the fee-payer key and submits via
  `eth_sendRawTransaction`);
- the `core/privacy/circuit` package directly for spend/transfer proving (which
  needs the wallet's own note set and Merkle tree).

The setup keys are **deterministic** (fixed public seed), so every node and prover
derives the identical proving/verifying keys — the property that lets a multi-node
devnet verify each other's proofs.

### Honest status of every privacy component (audit)

| Component | Status |
| --- | --- |
| Shielded-transfer circuit (membership, nullifier, balance, range) | Real; soundness-tested |
| Nullifier `nf = MiMC(ask, cm)` | Real; binds to the full note (fixed an earlier `MiMC(ask, rho)` collision foot-gun) |
| Shielded pool (MiMC tree, nullifier set, recent roots, VK registry) | Real; state-backed; root cross-checked against prover tree |
| Consensus settlement + fork gating + txpool gating | Real; block-processing integration-tested |
| EIP-5564 stealth addresses | Real; now hashes the compressed point per EIP-5564 (was x-coordinate only) |
| Pedersen commitments + `PEDERSEN_COMMIT/ADD`/`PLONK_VERIFY` precompiles | Real, general-purpose; **not** load-bearing for the shielded flow (which uses MiMC + a direct verifier) |
| Trusted setup | **Deterministic but insecure** (public seed); a real ceremony is the one remaining production blocker |
| Network-origin privacy (Dandelion++) | **Wired into the live broadcast path as a multi-hop stem; active by default on the privacy profile.** Persistent local-origin tracking (withheld from initial mempool sync until fluffed), originator-never-fluffs routing, multi-hop stem relay over the dedicated `dle` sub-protocol with multiple epoch-stable successors, per-node embargo failsafe, gossip fallback, and eclipse/connection-reset hardening (stability gating, subnet diversity, outbound preference, churn monitoring). Not a user opt-in — only an emergency/diagnostic `--dandelion.disable` override. Covered by router and multi-node tests. |
| Gas costs for shielded ops / precompiles | Real charging, **placeholder values** pending benchmarking |

### How a shielded transaction is processed (implemented)

1. The fee payer signs a `ShieldedTx` (secp256k1, like EIP-1559). Gas is charged
   normally; `value()` is always 0 — transparent value moves only via the pool.
2. `settleShielded` (gated by `Rules.IsPrivacy1`):
   anchor must be a known recent pool root → nullifiers must be unspent & unique →
   the PlonK proof must verify against the circuit's public inputs `(anchor,
   nullifiers, output commitments, valueBalance)` and the pool's installed
   verifying key → nullifiers are consumed, commitments appended → the signed
   `ValueBalance` is settled (shield debits the sender into the pool; unshield
   releases from the pool to `To`).

### Circuit (`core/privacy/circuit`)

The `Transfer` circuit is a 2-input/2-output JoinSplit over MiMC (BN254) that
constrains, in zero knowledge:

- **Membership**: each non-dummy input note's commitment is a leaf under the
  public `Anchor` (Merkle path verified with the same MiMC the consensus pool uses
  — the pool tree was migrated from Keccak to MiMC so the two agree).
- **Ownership + nullifier**: `nf = MiMC(ask, cm)` is correctly derived and equals
  the revealed nullifier; only the spending-key holder can produce it.
- **Commitment well-formedness**: each output commitment opens to its note.
- **Value conservation**: `Σ inputs = Σ outputs + valueBalance`, with 128-bit range
  checks that block field-wraparound "negative value" forgery.

Soundness is tested directly: value inflation, forged nullifiers, forged output
commitments and spends of non-member notes are all **unprovable**, and a valid
proof does not validate a transaction whose public fields were altered.

> **The one remaining caveat — trusted setup.** PlonK needs a universal SRS from a
> multi-party ceremony. The only SRS available today is generated in-process by
> `circuit.DevnetSetup` (gnark's `unsafekzg`); its toxic waste is known, so its
> verifying key must **never** be installed on a value-bearing network — anyone
> could forge proofs. This is now the sole blocker to production readiness for the
> circuit, and it is loudly documented at the call site and on the pool's
> `InstallVerifyingKey`. The circuit itself does not change when a real ceremony
> replaces the SRS; only the keys do.

---

## Encrypted mempool (part of the atomic privacy sprint)

Per `shape.md`, this is one client target with no internal phases. The
encrypted mempool is in scope for the sprint and is **not yet complete**: until it
decrypts and includes transactions end to end, the sprint as a whole is incomplete,
and that is stated plainly rather than dressed up as a shipped milestone.

The design is threshold-encryption based with an on-chain-registered keyper
committee (Shutter model) — not a local-only wallet mode and not commit-reveal.
A user threshold-encrypts an inner transaction to the committee (eon) key; the
ciphertext propagates and is buffered; and at block building a threshold of keypers
release decryption shares so the proposer can decrypt and include it. Transactions
that are never selected stay encrypted.

**Implemented and tested:**

- Threshold cryptosystem — [`core/privacy/threshold`](core/privacy/threshold): a
  verifiable hybrid threshold KEM/DEM over bn256 (`Encrypt` to the committee key,
  per-member decryption shares, pairing-based share verification for
  decryption-share accountability, Lagrange `Combine`).
- Verifiable distributed key generation — [`core/privacy/keyper/dkg.go`](core/privacy/keyper/dkg.go):
  a Pedersen/Feldman DKG so the committee key is generated with no single party
  holding the master secret (the trustless replacement for the trusted dealer).
- Threshold identity-based encryption — [`core/privacy/ibe`](core/privacy/ibe):
  Boneh-Franklin IBE over bn256 with the committee as private-key generator and the
  epoch as identity. This is the cryptographic per-epoch trigger: a transaction
  encrypted for epoch E is decryptable only with SK_E = s·H(E), which does not exist
  until a threshold of keypers release it, and is useless for any other epoch. The
  encrypted mempool encrypts with IBE, so future-epoch transactions are
  cryptographically undecryptable — not merely gated by keyper policy.
- Encrypted-tx envelope and buffer — [`core/privacy/encmempool`](core/privacy/encmempool):
  holds and moves only ciphertext; a never-included envelope exposes only
  ciphertext, recoverable solely with a committee threshold.
- Network propagation — [`eth/protocols/encmempool`](eth/protocols/encmempool):
  the `enc` sub-protocol floods envelopes across capable peers, advertised on the
  privacy network profile.
- On-chain keyper registry — [`core/privacy/keyper`](core/privacy/keyper): the
  consensus-readable committee record (threshold, keypers, and the IBE master public
  key wallets encrypt to), with a Solidity-compatible storage layout and a genesis
  populator.
- Decrypt-at-inclusion in block building — [`core/privacy/encmempool/decrypt.go`](core/privacy/encmempool/decrypt.go),
  [`eth/encrypted_inclusion.go`](eth/encrypted_inclusion.go), and the miner hook in
  [`miner/worker.go`](miner/worker.go): at block build, the proposer decrypts
  pending envelopes for which a committee threshold of shares is available, recovers
  the inner transactions, and commits them **directly into the block** (never the
  public pool, so contents are not revealed before inclusion). Already-included
  envelopes (nonce consumed) are dropped; undecryptable envelopes are skipped
  (committee-unavailable fallback); the path is gated behind the Privacy1 fork. A
  miner test confirms a decrypted transaction lands in the built block and not in
  the pool. Activated per node via `Ethereum.EnableEncryptedInclusion(registry,
  shareProvider)`.
- Keyper network — [`core/privacy/keyper/keypernet`](core/privacy/keyper/keypernet),
  vendored in-repo: a `Keyper` holds one DKG share and serves verifiable decryption
  shares; a `Transport` collects a threshold of verified shares for a ciphertext
  (an in-process transport for tests/single-operator devnets and an HTTP transport
  for independently-run keyper processes); and a `Provider` adapts the transport to
  the block builder's `ShareProvider`. `Bootstrap` runs the DKG and yields the
  committee. Tested end to end (encrypt → collect shares over the network → combine),
  including tolerance of down keypers and rejection of forged shares; and proven to
  drive the eth inclusion source so a transaction encrypted to the committee is
  decrypted for inclusion via the keyper network.
- Keyper daemon — [`cmd/keyper`](cmd/keyper): `bootstrap` runs the DKG and writes
  one secret key file per keyper plus a `committee.json` (eon key + registry storage
  for genesis); `serve` loads a key file and serves decryption shares over HTTP with
  two release controls — a shared-secret auth token (only proposers presenting it
  are served) and an enable trigger (the operator can pause release). These controls
  stop arbitrary parties from decrypting the encrypted mempool. Key files are
  written 0600; tested for round-trip and committee export.
- Submit RPC — [`eth/encmempool_api.go`](eth/encmempool_api.go): `privacy_sendEncryptedTransaction`
  accepts a client-encrypted ciphertext envelope, validates it, and buffers+gossips
  it (the node never sees plaintext); `privacy_committee` reports the IBE master
  public key, threshold, and keypers from the on-chain registry so wallets can
  encrypt to the committee for a target epoch.

Per-epoch gating is now cryptographic: the keyper auth/enable/epoch-trigger controls
are defence in depth, but even without them a future epoch's transactions are
undecryptable because the epoch key does not exist until the committee releases it.

Batched threshold encryption (USENIX Security 2024/2025) and BEAT-MEV are the
research directions to track for efficiency (one IBE key release per epoch is
already efficient; batching would further amortise committee work). Fair-ordering/PBS
hooks are future roadmap context, not part of the current client target.

---

## Future roadmap (beyond the client target): private tokens, contracts & post-quantum

**Goal.** Extend confidentiality beyond ETH to tokens and arbitrary computation,
then migrate cryptography to be quantum-resistant.

### Workstreams

1. **Confidential ERC-20 / ERC-721 (Roadmap Ph.2).**
   - Generalise the shielded pool to multi-asset notes (asset id inside the
     commitment). Reference contracts + an EIP draft for the standard.
   - Reuse nullifiers/commitments; add shielded NFT ownership notes.

2. **Private smart-contract execution (Roadmap Ph.3 §1–§2).**
   - Integrate a zkVM execution path (RISC Zero / Polygon Miden style) able to prove
     EVM/sub-circuit execution. Start with a precompile that verifies a zkVM receipt
     for a constrained DSL; grow toward a full zkEVM.
   - Standard library of audited private DeFi primitives (swap/lend) à la
     OpenZeppelin.

3. **Post-quantum migration (Roadmap Ph.5).**
   - Add lattice/hash-based signature verification (CRYSTALS-Dilithium, SPHINCS+)
     selectable via account abstraction, allowing legacy + PQ accounts to coexist.
   - Migrate the proof system from pairing-based SNARKs to **zk-STARKs**
     (transparent, no trusted setup, PQ-friendly). Swap the PlonK verifier
     for a STARK verifier behind a new fork.
   - PQ signature aggregation to manage larger signature sizes.

### Exit criterion
Confidential token transfers interoperate with shielded ETH in one anonymity set;
a sample contract executes privately end-to-end; a PQ-signed account transacts and
a STARK-verified shielded transfer validates on a devnet.

---

## Cross-cutting concerns (client-wide)

- **Fork management.** Each phase = one fork flag in `params.ChainConfig`/`Rules`;
  default-off on mainnet config. Devnet genesis activates them at block/time 0.
- **Testing.** Per-phase: unit (crypto), state-transition, txpool, and a
  multi-node devnet integration test. Add fuzzers for proof/tx decoders.
- **Auditing.** Circuits and consensus-critical verification get external review
  before any non-devnet activation (Roadmap Ph.5 "ongoing audits").
- **Performance.** Track proof verify gas, proving time, and proof size as release
  gates (Roadmap targets: sub-5s proving, competitive verify cost).
- **Backwards compat.** Public transactions remain first-class; privacy is additive
  and opt-in at the protocol layer until a later governance decision makes it
  default (Roadmap Ph.4).

## Engineering order within the client target

Internal build order only — these are one client target, not separate deliverables:

```
confidential ETH (consensus shielded transfers)   — largest consensus surface
Dandelion++ network-origin privacy                — independent of state changes
encrypted mempool (threshold/IBE + keyper + inclusion)
```

Future roadmap (private tokens, computation, post-quantum) builds on the shielded
pool and is out of scope for the current client target.
