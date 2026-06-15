# Sovereign Privacy: Three-Phase Implementation Plan

This document maps the five-phase research roadmap *"Ethereum Privacy: The Road to
Self-Sovereignty"* onto **three concrete, buildable engineering phases** for this
go-ethereum client. It builds directly on the foundation already merged to `master`
(see [`PRIVACY_ROADMAP.md`](PRIVACY_ROADMAP.md)): Pedersen commitments, EIP-5564
stealth addresses, Dandelion++ routing, the shielded-pool primitives, and the
`PEDERSEN_COMMIT`/`PEDERSEN_ADD` precompiles.

Each engineering phase is independently shippable, gated behind a hard fork so
mainnet semantics never change until activation, and ends with a clear,
testable exit criterion.

## Mapping: roadmap phases → engineering phases

| Engineering phase | Pulls from roadmap | Theme |
| --- | --- | --- |
| **Phase 1 — Confidential ETH (consensus)** | Roadmap Ph.1 §1, Ph.3 §3, Ph.4 §1 | Make the merged primitives *consensus-real*: a shielded ETH pool with a private transfer transaction. |
| **Phase 2 — Mempool & network privacy** | Roadmap Ph.1 §2–§3, Ph.4 §3 | Protect transactions *before* inclusion: encrypted mempool, Dandelion++, fair ordering. |
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
     `gnark-crypto` is present today) and a **Groth16 verifier precompile**
     (`0x14`) plus range-proof support, fulfilling Roadmap Ph.3 §3 ("precompiles
     for verifying common zk-SNARK schemes").
   - The shielded transfer circuit proves: input notes exist in the tree (Merkle
     membership), nullifiers are correctly derived, output commitments are
     well-formed, and `Σ inputs = Σ outputs + valueBalance` (reuse the Pedersen
     homomorphism / `PEDERSEN_ADD`).
   - Circuits live in a new `core/privacy/circuits/` package with a checked-in
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

### Exit criterion
A devnet where `privacy_transfer` moves shielded ETH between two parties such that
the public trace reveals neither amount nor the sender↔recipient link, validated by
a full sync of a third node. Unit + state tests green; `go test ./core/...`.

### Key decisions to settle first
- **Proof system**: Groth16 (smallest proofs/cheapest verify, per-circuit trusted
  setup) vs PlonK/Halo2 (universal setup). Roadmap cites both. Recommend Groth16
  for v1 verify-cost, migrate to Halo2 in Phase 3.
- **Pool model**: single ETH pool vs multi-asset (defer multi-asset to Phase 3).

---

## Phase 2 — Mempool & network privacy (anti-MEV, anti-surveillance)

**Goal.** Transaction *content and origin* are protected before inclusion,
neutralising front-running/sandwiching and IP-level deanonymisation. Largely
independent of Phase 1.

### Workstreams

1. **Dandelion++ wiring (Roadmap Ph.1 §3).**
   - Integrate the merged `p2p/dandelion.Router` into `eth/handler.go`
     `BroadcastTransactions` (`:452`), behind a `--privacy.dandelion` flag.
   - Stem locally-originated txs to the per-epoch successor; fall back to diffusion
     for received txs already in fluff. Run the embargo loop in `txBroadcastLoop`
     (`:508`); call `MarkFluffed` when a tx arrives via normal gossip.
   - Feed `SetPeers` from the peer set on connect/disconnect.

2. **Encrypted mempool (Roadmap Ph.1 §2, Ph.4 §3).**
   - Commit-reveal first: peers gossip a commitment to the tx; the payload is
     revealed only at/after inclusion. New `p2p/dandelion`-adjacent package
     `core/txpool/encrypted/`.
   - Then threshold encryption: txs encrypted to a validator-set key, decrypted on
     inclusion via a threshold scheme (Shamir). Inspired by Shutter Network. This
     is the largest sub-project; stage it behind commit-reveal.

3. **Fair ordering & PBS hooks (Roadmap Ph.4 §3).**
   - Expose an ordering hook in the miner/builder path
     (`miner/`) so encrypted/committed txs are ordered before decryption.
   - Optional VDF-based or commit-reveal sortition for proposer-neutral ordering.

### Exit criterion
On a multi-node devnet: (a) a transaction's origin node is not identifiable from
announcement timing across N adversarial observers (Dandelion++ statistical test);
(b) tx contents are unavailable to the proposer until ordering is fixed
(commit-reveal integration test).

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
     (transparent, no trusted setup, PQ-friendly). Swap the Phase 1 Groth16 verifier
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
