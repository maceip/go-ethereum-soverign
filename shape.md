# Sovereign Privacy Shape

This document is the alignment source for this fork. The attached roadmap,
*"Ethereum Privacy: The Road to Self-Sovereignty"*, is the source of truth for
scope and phase placement. Existing implementation notes must be read through
this document when there is any tension.

## Atomic Sprint

This fork does not have multiple implementation phases. The roadmap's phase
labels are source-context only: they explain why a requirement belongs in scope,
not permission to defer it into a later fork milestone.

The current privacy overhaul is one atomic sprint. Dandelion++, confidential ETH,
the opinionated privacy defaults, the required cleanup, and the documented
research-aligned scope must land together as one coherent production shape or be
called incomplete. Do not split the work into "Phase 1 now, Phase 2 later" inside
this fork, and do not merge partial privacy paths that create a user-visible
guarantee gap.

## Non-Negotiable Phase Alignment

Dandelion++ is a core Phase 1 requirement. It is not a Phase 2 module, not an
optional experiment, and not a cleanup item that can be removed without replacing
the Phase 1 network-origin privacy it was meant to provide.

The roadmap places network-level anonymity under Phase 1, "Early MEV Protection
& Network Privacy":

- Phase 1 protects native ETH transaction privacy before inclusion, not only
  after execution.
- Hiding sender, recipient, and amount on-chain is insufficient if peer-to-peer
  propagation still reveals the origin node.
- Dandelion++ is the first client-level mechanism in this fork for obscuring
  transaction origin and reducing timing-based deanonymization.

If Dandelion++ is not wired into the transaction propagation path, the fork must
state plainly that Phase 1 network-origin privacy is incomplete. It must not be
described as Phase 2 work.

## Opinionated Privacy Defaults

This fork should ship as an opinionated privacy client, not as a bag of
user-selected privacy switches. Privacy behavior that is part of the roadmap
must be active by default when the node is running on a network where the
corresponding privacy fork or network profile is active.

- Do not add user-side opt-in flags for core privacy guarantees. A user should
  not have to know which network privacy, mempool privacy, or shielded-transfer
  toggles to enable in order to receive the baseline protection promised by the
  roadmap.
- Any operational override must be scoped as development, test, emergency, or
  compatibility tooling. It must not be presented as a normal product path and
  must make the resulting privacy gap observable in logs and metrics.
- Tuning parameters may exist for devnets, simulations, and benchmark harnesses,
  but production defaults must be opinionated, documented, and safe to run
  without local customization.
- RPC and wallet helpers may expose status and diagnostics, but they must not
  turn core privacy features into optional per-user behavior.

## Dandelion++ Acceptance Criteria

A Dandelion++ implementation is acceptable only when it is wired into the live
client path and covered by propagation tests. A standalone router package is not
enough.

- Locally originated transactions enter stem phase by default when the node has
  an eligible stem peer.
- The implementation preserves phase semantics for local, stem-relayed, and
  fluff/diffusion transactions.
- Normal Ethereum gossip remains the safety fallback when Dandelion routing
  cannot safely proceed.
- An embargo fallback exists for stemmed transactions and is observable through
  logs or metrics.
- Fluffed transactions cancel any local embargo state for the same hash.
- Peer selection is epoch-stable enough to prevent trivial timing averaging, and
  epoch rotation is tested.
- The implementation is active by default on the privacy network profile. Any
  disable path is a clearly-labelled devnet, compatibility, or emergency escape
  hatch, not a user-facing privacy preference.
- Multi-peer tests cover origin-obfuscation behavior; unit tests for a router
  alone do not satisfy the requirement.
- The Dandelion++ design includes eclipse and connection-reset hardening. Recent
  Monero research shows that Dandelion++ can be weakened if peer-management
  rules let an adversary repeatedly reset or monopolize the stem path.

## Required Dandelion++ Touchpoints

Dandelion++ must be integrated across the transaction lifecycle, not bolted onto
one helper.

- `eth/handler.go` transaction broadcast path:
  `BroadcastTransactions` must choose stem or fluff behavior for local
  transactions instead of always using the existing direct-send/announcement
  split.
- Transaction origin tracking:
  the client must distinguish locally originated transactions from remote
  transactions submitted by peers. Sources include RPC submission, local wallet
  paths, miner/local tx paths, and remote peer propagation.
- Txpool event surface:
  `core.NewTxsEvent` or the surrounding txpool event plumbing must carry enough
  locality metadata for the handler to know whether a transaction should start in
  stem phase.
- Peer selection:
  the router must track eligible peers, update on connect/disconnect, select a
  per-epoch successor, and fall back to diffusion when no safe successor exists.
- `ethPeer` send and announce APIs:
  stem relay must use the correct peer-level transaction send path, while fluff
  must use normal broadcast/announcement behavior.
- Inbound transaction handling:
  normal gossip receipt must mark a transaction as fluffed so embargo state is
  cancelled and duplicate fallback broadcasts are avoided.
- Embargo loop:
  the handler must periodically diffuse expired embargoes and expose enough
  observability to prove fallback is working.
- Config and flags:
  Dandelion++ must not rely on an end-user opt-in flag. Production nodes on the
  privacy network profile use it by default. Parameters such as stem
  probability, epoch duration, embargo base delay, and embargo jitter belong in
  network defaults and test/devnet harnesses; override flags must be labelled as
  diagnostics, compatibility, or emergency controls.
- Metrics and logs:
  track stem sends, fluff broadcasts, embargo expiries, peer-selection fallback,
  suspected eclipse or connection-reset pressure, and any emergency/diagnostic
  disabled-path fallback.
- Tests and simulations:
  include a multi-node propagation harness with adversarial observers, plus tests
  for local submission, remote relay, epoch rotation, embargo expiry, peer loss,
  connection churn, eclipse attempts, and rebroadcast/reorg behavior.

## 2024-2026 Research Updates To Fold In

The recent privacy literature changes the implementation shape. The most useful
work is not a replacement for the confidential ETH vertical slice; it is a set
of constraints for network privacy, encrypted mempools, validator accountability,
and proving UX.

Do not treat Algorand-specific LSAG/ring-signature designs as part of this fork's
target architecture. They are useful as contrast, but they do not fit the
Ethereum client, transaction, and validator surface this fork is modifying.

### Network-Origin Privacy

- Dandelion++ remains Phase 1, but it must be implemented with peer-management
  hardening. The 2025 NDSS Monero eclipse-attack work is directly relevant
  because Monero is the production Dandelion++ deployment to learn from, and the
  attack class targets the surrounding P2P connection manager as much as the
  transaction relay algorithm.
- The implementation must monitor and test connection churn, biased stem-peer
  selection, outbound-slot monopolization, repeated disconnect/reconnect
  pressure, and timing observation by adversarial peers.
- Dandelion++ is the first hop of origin protection, not the whole privacy
  story. It should compose with encrypted mempool work instead of being used as
  an excuse to defer encrypted mempool design.

### Encrypted Mempool Direction

Phase 1 encrypted mempool work should be scoped around threshold encryption, with
batched threshold encryption as the research direction to track. The strongest
current line of work is:

- "Shutter Network: Private Transactions from Threshold Cryptography" (ePrint
  2024/1981): useful as a deployed threshold-encryption reference, but not as a
  design to copy uncritically because later work identifies concrete security
  pitfalls in earlier encrypted-mempool constructions.
- "Mempool Privacy via Batched Threshold Encryption: Attacks and Defenses"
  (USENIX Security 2024): establishes the batched threshold-encryption framing,
  including privacy for transactions that are not selected in the current batch.
- "Practical Mempool Privacy via One-time Setup Batched Threshold Encryption"
  (USENIX Security 2025): improves deployability by using a one-time DKG setup
  for decryption servers.
- "BEAT-MEV: Epochless Approach to Batched Threshold Encryption for MEV
  Prevention" (USENIX Security 2025): removes costly per-epoch setup and is the
  best current candidate to study for a practical client roadmap.
- "BlindPerm: Efficient MEV Mitigation with an Encrypted Mempool and
  Permutation" (OPODIS 2025): useful because encrypted mempools alone do not
  fully solve ordering manipulation; permutation and ordering commitments need
  to be considered with the encryption design.
- "Efficiently-Thresholdizable Batched Identity Based Encryption, with
  Applications" (ePrint 2024/1575) and weighted BTE follow-up work are useful
  for committee and validator-weighted settings.

The implementation implication is concrete: do not build an encrypted mempool as
a local-only optional wallet mode. It needs a network-level committee/decryption
model, ciphertext propagation path, inclusion rules, fallback behavior, and
tests for pending-transaction privacy when transactions are not included.

### Threshold Accountability

Threshold encryption creates a new collusion and key-release surface. The fork
should track traceable threshold-encryption work, including 2025 research on
CCA-secure traceable threshold encryption, as a requirement source for:

- identifying or deterring decryption-share abuse;
- specifying validator or committee accountability when early decryption occurs;
- logging enough evidence for protocol-level or operator-level response;
- avoiding designs where a small coalition can silently deanonymize pending
  transactions without attribution.

### Shielded Pool Scale And Decoys

"Toxic Decoys" (ePrint 2025/1124) is relevant to shielded-pool scaling because
it studies randomized partitioning and decoy structure for scalable
untraceability. This fork should not immediately import a new anonymity-set
construction, but it should avoid baking in data structures that make decoys,
partitioning, or accumulator-backed scaling impossible later.

### Proving UX And Operations

PlasmaBlind and related 2026 client-side proving work are useful signals for
user experience: private transaction proving must become fast enough for normal
wallet flows. The fork should keep proof-generation APIs, wallet helpers, and
benchmark targets compatible with client-side or delegated proving strategies.

Operationally, proof orchestration work such as `push0` is relevant to prover
service design. It does not replace protocol logic, but it is a useful model for
observable, retryable, event-driven proof generation when local proving is too
slow.

Optional source-of-funds or compliance proofs should remain separate,
user-initiated compatibility tools. They must not become a core validity rule or
a default privacy-path dependency.

### Research Source List

Use these as the current research inputs for implementation design:

- Arka Rai Choudhuri, Sanjam Garg, Julien Piet, Guru-Vamsi Policharla,
  "Mempool Privacy via Batched Threshold Encryption: Attacks and Defenses",
  USENIX Security 2024:
  https://www.usenix.org/conference/usenixsecurity24/presentation/choudhuri
- Stefan Dziembowski, Sebastian Faust, Jannik Luhn, "Shutter Network: Private
  Transactions from Threshold Cryptography", Cryptology ePrint 2024/1981:
  https://eprint.iacr.org/2024/1981
- Arka Rai Choudhuri, Sanjam Garg, Julien Piet, Guru-Vamsi Policharla,
  "Practical Mempool Privacy via One-time Setup Batched Threshold Encryption",
  USENIX Security 2025:
  https://www.usenix.org/conference/usenixsecurity25/presentation/choudhuri
- Jan Bormet, Sebastian Faust, Hassan Othman, Zhenfei Qu, "BEAT-MEV:
  Epochless Approach to Batched Threshold Encryption for MEV Prevention",
  USENIX Security 2025:
  https://www.usenix.org/conference/usenixsecurity25/presentation/bormet
- Alireza Kavousi, Duc Viet Le, Philipp Jovanovic, George Danezis, "BlindPerm:
  Efficient MEV Mitigation with an Encrypted Mempool and Permutation", OPODIS
  2025:
  https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.OPODIS.2025.36
- Ruisheng Shi, Zhiyuan Peng, Lina Lan, Yulian Ge, Peng Liu, Qin Wang, Juan
  Wang, "Eclipse Attacks on Monero's Peer-to-Peer Network", NDSS 2025:
  https://www.ndss-symposium.org/ndss-paper/eclipse-attacks-on-moneros-peer-to-peer-network/
- "Efficiently-Thresholdizable Batched Identity Based Encryption, with
  Applications", Cryptology ePrint 2024/1575:
  https://eprint.iacr.org/2024/1575
- "CCA-Secure Traceable Threshold (ID-based) Encryption and Application",
  Cryptology ePrint 2025/341:
  https://eprint.iacr.org/2025/341
- "Toxic Decoys", Cryptology ePrint 2025/1124:
  https://eprint.iacr.org/2025/1124
- Pierre Daix-Moreux, Chengru Zhang, "PlasmaBlind: A Private Layer 2 With
  Instant Client-Side Proving", Cryptology ePrint 2026/634:
  https://eprint.iacr.org/2026/634
- Reilabs, "push0: Scalable and Fault-Tolerant Orchestration for Zero-Knowledge
  Proof Generation", arXiv 2026:
  https://arxiv.org/abs/2602.16338
- "Proof of Source of Funds: Efficient On-chain Provenance of Cryptoassets",
  arXiv 2026:
  https://arxiv.org/abs/2606.10172

## Simplify, Scope, Reduce

The fork should remain narrow, auditable, and wired. Privacy code must either be
on a production path with tests or clearly quarantined as non-production tooling.

- Remove or quarantine dead privacy modules. Do not keep packages that are not
  imported by the client path unless they are explicitly marked as test fixtures
  or research prototypes.
- Privacy1 fork gating is the only activation path for privacy consensus
  changes. No precompile, transaction type, or state-transition behavior should
  become active merely because an unrelated fork is active.
- Devnet trusted setup remains devnet-only. Any deterministic or insecure setup
  must be impossible to mistake for value-bearing network readiness.
- Placeholder gas constants must stay labelled as placeholders until benchmarked
  against realistic proof sizes and verification costs.
- Avoid competing roadmap documents. `shape.md` owns scope and phase alignment;
  other docs may describe status, but they must not reclassify Phase 1 items.
- Every privacy feature needs one wired path and one verification story. Tests
  should cover the path users or nodes actually exercise.
- Do not add optional user-facing privacy modes for roadmap requirements. The
  default client path must be the private path on supported networks.
- Do not ship "privacy" APIs that imply guarantees the client does not provide.
  If a feature is a helper, say helper. If it is incomplete, say incomplete.
- Keep protocol changes minimal and explicit. New dependencies, precompiles,
  transaction types, reserved addresses, and RPC methods must each map to a
  roadmap target and a testable acceptance criterion.
- Scope wallet conveniences separately from consensus. RPC helpers may make
  wallet integration easier, but they do not substitute for protocol or network
  privacy.
- Reject vague deferrals. If the attached roadmap places an item in Phase 1,
  this fork must not move it out of the atomic sprint without explicitly
  documenting the reason and the privacy gap it creates.

## Current Review

Review date: 2026-06-16.

Reviewed remote state after `git fetch --all --prune`:

- `origin/master` was unchanged at
  `a9ab4ec9f7310741ff48d44d260339e348d769cc`.
- `origin/claude/go-ethereum-client-mods-8sz2dl` contained Dandelion++ work in
  `1091718a3 eth, p2p/dandelion: wire Dandelion++ network-origin privacy into
  the live tx path`, followed by
  `fae8f09e8 shape: record Dandelion++ design corrections from initial-design
  review`.

The remote work branch is useful, but it is not implementation-complete against
this shape document and should not be treated as merge-ready without follow-up.

Implemented on that branch:

- `p2p/dandelion/dandelion.go` restores a Dandelion++ router package.
- `eth/handler.go` and `eth/handler_dandelion.go` wire Dandelion routing into
  the live transaction broadcast path.
- `eth/api_backend.go` marks RPC `SendTx` submissions as local-origin.
- Peer connect/disconnect refreshes the Dandelion eligible-peer set.
- Inbound transaction gossip marks hashes as fluffed and cancels local embargo
  state.
- An embargo loop diffuses expired stemmed transactions as a safety fallback.
- Tests cover one-hop stem delivery, remote transaction diffusion, embargo
  fallback, router behavior, and basic origin-tracker behavior.

Blocking gaps against this shape:

- The branch adds normal user-facing opt-in and tuning flags:
  `--dandelion`, `--dandelion.stemprob`, `--dandelion.epoch`,
  `--dandelion.embargo`, and `--dandelion.embargojitter`. This conflicts with
  the requirement that roadmap privacy works out of the box on supported privacy
  networks and is not presented as a normal user preference.
- The implementation is single-hop, not full Dandelion++. Stem relay uses the
  ordinary eth transaction send path, so the receiving peer cannot identify the
  transaction as stem-phase traffic and continue stemming it.
- Local transactions can still fluff at the origin because the same stem/fluff
  coin is applied at hop zero. Local-origin transactions should enter stem phase
  whenever an eligible successor exists.
- Local-origin tracking is consume-once and is fed by RPC `SendTx` only. It does
  not persist across rebroadcasts and does not cover local wallet, miner,
  journal-resurrected, or locally-resubmitted transactions.
- Peer selection uses a single epoch successor. It does not implement at least
  two deterministic per-epoch successors or hardening against churn and
  successor monopolization.
- Eclipse and connection-reset hardening is not implemented. Metrics cover stem,
  fluff, embargo, and peer fallback, but not suspected eclipse pressure,
  connection-reset pressure, or churn-based manipulation.
- The branch's `shape.md` is based on an older document and drops the current
  opinionated-defaults and 2024-2026 research sections. Any merge must preserve
  the current `shape.md` content and add the Dandelion design corrections on top.
- Encrypted mempool, batched threshold encryption, threshold accountability,
  shielded-pool decoy scaling, source-of-funds compatibility proofs, and prover
  orchestration remain document-level direction only. No implementation was found
  for those items.

Required before merge:

- Rebase the Dandelion branch onto current `origin/master` and preserve this
  document's latest requirements.
- Replace normal user opt-in flags with opinionated network/profile defaults.
  Any override must be clearly scoped as devnet, diagnostic, compatibility, or
  emergency tooling.
- Add an explicit stem-relay signal or subprotocol so honest relays can continue
  stem propagation beyond one hop, with fallback to ordinary gossip for peers
  that do not support it.
- Split origin and relay routing semantics so originators never randomly fluff
  when a stem successor is available.
- Make local-origin state persistent until fluff sighting, inclusion, or bounded
  expiry, and mark all local submission/resubmission paths.
- Replace single-successor routing with at least two deterministic per-epoch
  successors and tests for churn resistance.
- Add tests for multi-hop stem propagation, rebroadcast behavior, non-RPC local
  paths, peer churn, successor loss, and eclipse/connection-reset pressure.

## Current Alignment Notes

- Confidential ETH state transition work is Phase 1.
- Stealth address support is Phase 1.
- Dandelion++ network-origin privacy is Phase 1 and currently incomplete until
  wired into live propagation.
- Encrypted mempool work is also Phase 1. It may be sequenced after Dandelion++
  inside the same atomic sprint, but it is not a separate phase or a later merge
  target. The target shape must account for modern threshold-encryption and
  batched-threshold-encryption research before the sprint is considered complete.
- Privacy precompiles are Phase 3 roadmap material and must remain gated by the
  Privacy1 fork while this fork uses them as enabling infrastructure.
- Protocol-native shielded-pool integration overlaps Phase 4, but this fork's
  current shielded ETH vertical slice is acceptable only because it is explicitly
  gated and devnet-scoped until production cryptographic setup exists.

## Done Means

No privacy feature is considered done because code exists. It is done only when:

- the phase placement matches the attached roadmap;
- the code is wired into the intended client path;
- unsupported paths fail closed or are explicitly labelled;
- tests cover the real path, not just isolated helpers;
- docs describe the actual guarantee, not the desired future guarantee.
