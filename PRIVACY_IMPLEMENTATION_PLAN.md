# Sovereign Privacy: Three-Phase Implementation Plan

This document maps the five-phase research roadmap *"Ethereum Privacy: The Road to
Self-Sovereignty"* onto **three concrete, buildable engineering phases** for this
go-ethereum client. It builds directly on the foundation already merged to `master`
(see [`PRIVACY_ROADMAP.md`](PRIVACY_ROADMAP.md)): Pedersen commitments, EIP-5564
stealth addresses, the shielded-pool primitives, and the
`PEDERSEN_COMMIT`/`PEDERSEN_ADD` precompiles.

[`shape.md`](shape.md) is the canonical alignment document. In particular,
Dandelion++ network-origin privacy is a **Phase 1 core requirement** under the
source roadmap, not Phase 2 work.

Each engineering phase is independently shippable, gated behind a hard fork so
mainnet semantics never change until activation, and ends with a clear,
testable exit criterion.

## Mapping: roadmap phases → engineering phases

| Engineering phase | Pulls from roadmap | Theme |
| --- | --- | --- |
| **Phase 1 — Confidential ETH + network-origin privacy** | Roadmap Ph.1 §1–§4, Ph.3 §3, Ph.4 §1 | Make ETH private end-to-end enough for Phase 1: shielded transfer plus Dandelion++ origin protection. |
| **Phase 2 — Encrypted mempool & fair ordering** | Roadmap Ph.1 §2, Ph.4 §3 | Protect transaction contents and ordering before inclusion: encrypted mempool and fair ordering. |
| **Phase 3 — Private tokens, contracts & PQ** | Roadmap Ph.2, Ph.3 §1–§2, Ph.5 | Generalise privacy to tokens and computation, then quantum-harden. |

**Recommended ordering: 1 → 2 → 3.** The roadmap itself states Phase 1 is
foundational ("if ETH remains public, private ERC-20/721 transactions still reveal
links"). Phase 2 is independent of Phase 1 and can run in parallel if staffing
allows. Phase 3 depends on both.

---

## Phase 1 — Confidential ETH transactions (consensus-level)

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
  deferred to Phase 3 (post-quantum).
- **Pool model**: single ETH pool vs multi-asset (defer multi-asset to Phase 3).

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

`geth --dev --dev.privacy` brings up a developer chain with Privacy Phase 1 active
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

## Encrypted mempool (Phase 1) & fair ordering (later)

**Goal.** Transaction *content* is protected before inclusion, neutralising
front-running/sandwiching and surveillance of pending transactions. Per `shape.md`
the encrypted mempool is a **Phase 1** item (threshold-encryption based,
stage-able after Dandelion++); fair-ordering/PBS hooks are later-phase roadmap
work. Dandelion++ origin privacy is the other Phase 1 network-privacy item.

### Workstreams

1. **Encrypted mempool — Phase 1, threshold-encryption based (Roadmap Ph.1 §2).**
   Per `shape.md`, this is Phase 1 (stage-able after Dandelion++) and is scoped
   around threshold encryption — not a local-only wallet mode and not commit-reveal.
   It is being built in honest, independently-tested stages:

   - **Stage 1 — threshold cryptosystem (DONE).**
     [`core/privacy/threshold`](core/privacy/threshold) implements a verifiable
     hybrid threshold KEM/DEM over bn256: trusted-dealer (devnet) `(t,n)` setup,
     `Encrypt` to a committee key, per-member decryption shares, pairing-based
     share verification (so decryption-share abuse is detectable — the
     accountability hook), and Lagrange `Combine`. Tested for correctness,
     threshold (t-1 cannot decrypt), foreign-share rejection, share verifiability,
     duplicate-index rejection, and serialization. Trusted-dealer setup is
     devnet-only and clearly labelled, mirroring the shielded trusted-setup posture;
     production requires a DKG.
   - **Stage 2a — encrypted-tx envelope and mempool buffer (DONE).**
     [`core/privacy/encmempool`](core/privacy/encmempool) provides an `Envelope`
     wrapping a Stage-1 ciphertext (identified by its content hash) and a bounded,
     concurrency-safe `Pool` that holds and moves only ciphertext. Tested for
     dedup/eviction and for the core privacy property: a buffered envelope that is
     never included exposes only ciphertext, and its plaintext is recoverable only
     with a threshold of committee decryption shares.
   - **Stage 2b — network propagation (NEXT).** A dedicated `enc` sub-protocol that
     gossips encrypted envelopes between capable peers, so the encrypted mempool is
     network-level rather than a local-only buffer, with multi-node propagation
     tests.
   - **Stage 3 — committee decryption and block inclusion.** Share collection at
     inclusion time, proposer-side combination/decryption before execution,
     inclusion/ordering rules, fallback when the committee is unavailable, and
     accountability logging. This stage is consensus-adjacent and gated behind the
     privacy fork.

   Batched threshold encryption (USENIX Security 2024/2025) and BEAT-MEV are the
   research directions to track for Stage 3 efficiency; the Stage 1 interfaces do
   not preclude moving to a batched scheme.

2. **Fair ordering & PBS hooks (Roadmap Ph.4 §3).**
   - Expose an ordering hook in the miner/builder path
     (`miner/`) so encrypted/committed txs are ordered before decryption.
   - Optional VDF-based or commit-reveal sortition for proposer-neutral ordering.

### Exit criterion
On a multi-node devnet, tx contents are unavailable to the proposer until ordering
is fixed (commit-reveal integration test).

### Key decision
Encrypted-mempool design: **commit-reveal** (simpler, ships first, weaker
guarantees) vs **threshold encryption** (stronger, needs validator-key DKG and
consensus changes). Recommend shipping commit-reveal, then threshold.

---

## Phase 3 — Private tokens, contracts & post-quantum

**Goal.** Extend confidentiality beyond ETH to tokens and arbitrary computation,
then migrate cryptography to be quantum-resistant.

### Workstreams

1. **Confidential ERC-20 / ERC-721 (Roadmap Ph.2).**
   - Generalise the Phase 1 shielded pool to multi-asset notes (asset id inside the
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
     (transparent, no trusted setup, PQ-friendly). Swap the Phase 1 PlonK verifier
     for a STARK verifier behind a new fork.
   - PQ signature aggregation to manage larger signature sizes.

### Exit criterion
Confidential token transfers interoperate with shielded ETH in one anonymity set;
a sample contract executes privately end-to-end; a PQ-signed account transacts and
a STARK-verified shielded transfer validates on a devnet.

---

## Cross-cutting concerns (all phases)

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

## Suggested sequencing

```
Phase 1  ──────────────►  (consensus confidential ETH)         ~ largest, gates Ph.3
   │
   ├─ Phase 2 can start in parallel (network/mempool, independent of state changes)
   │
   └─────────────────────►  Phase 3 (needs Ph.1 pool + Ph.2 ordering)
```
