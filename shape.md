# Sovereign Privacy Shape

This document is the alignment source for this fork. The attached roadmap,
*"Ethereum Privacy: The Road to Self-Sovereignty"*, is the source of truth for
scope and required privacy guarantees. Existing implementation notes must be read
through this document when there is any tension.

## Single Client Target

This fork is not a staged, phased, demo, beta, preview, or partial-delivery
effort. It is one client moving toward one production privacy shape. Any
document, branch, issue, or implementation note that presents the privacy work as
separate spaces, tracks, slices, fallback paths, or differently branded delivery
buckets must be corrected or read through this file.

The client target includes Dandelion++, confidential ETH, opinionated privacy
defaults, encrypted-mempool direction, required cleanup, and the documented
research-aligned scope. These are not separately branded milestones. Work can be
ordered internally for engineering reasons, but partial paths must be described
as incomplete implementation work, not as a valid lower-tier client mode.

Do not use labels such as stage, phase, demo, beta, preview, vertical slice,
later milestone, or optional module to make an incomplete privacy path sound
acceptable. There is one supported client goal: it works out of the box on the
supported privacy network profile, with the documented privacy guarantees wired
into the real client paths and covered by tests.

Fallback code is allowed only for explicit liveness, compatibility, emergency, or
recovery handling. It must never be the product path, the testing substitute, or
the reason a missing privacy implementation is described as working.

## Non-Negotiable Client Alignment

Dandelion++ is a core requirement of the client. It is not a secondary module,
not an experiment, and not a cleanup item that can be removed without replacing
the network-origin privacy it was meant to provide.

- Native ETH transaction privacy must be protected before inclusion, not only
  after execution.
- Hiding sender, recipient, and amount on-chain is insufficient if peer-to-peer
  propagation still reveals the origin node.
- Dandelion++ is the first client-level mechanism in this fork for obscuring
  transaction origin and reducing timing-based deanonymization.

If Dandelion++ is not wired into the transaction propagation path, the fork must
state plainly that network-origin privacy is incomplete. It must not be
reclassified into a separate delivery bucket.

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

- Locally originated transactions enter stem routing by default when the node has
  an eligible stem peer.
- The implementation preserves Dandelion routing semantics for local, stem-relayed, and
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
  stem routing.
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
work is not a replacement for confidential ETH; it is a set
of constraints for network privacy, encrypted mempools, validator accountability,
and proving UX.

Do not treat Algorand-specific LSAG/ring-signature designs as part of this fork's
target architecture. They are useful as contrast, but they do not fit the
Ethereum client, transaction, and validator surface this fork is modifying.

### Network-Origin Privacy

- Dandelion++ remains required client functionality, but it must be implemented
  with peer-management hardening. The 2025 NDSS Monero eclipse-attack work is
  directly relevant because Monero is the production Dandelion++ deployment to
  learn from, and the attack class targets the surrounding P2P connection
  manager as much as the transaction relay algorithm.
- The implementation must monitor and test connection churn, biased stem-peer
  selection, outbound-slot monopolization, repeated disconnect/reconnect
  pressure, and timing observation by adversarial peers.
- Dandelion++ is the first hop of origin protection, not the whole privacy
  story. It should compose with encrypted mempool work instead of being used as
  an excuse to defer encrypted mempool design.

### Encrypted Mempool Direction

Encrypted mempool work should be scoped around threshold encryption, with batched
threshold encryption as the research direction to track. The strongest current
line of work is:

- "Shutter Network: Private Transactions from Threshold Cryptography" (ePrint
  2024/1981): useful as a deployed threshold-encryption reference, but not as a
  design to copy uncritically because newer work identifies concrete security
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

### Block Propagation And Inclusion Path

The privacy client is incomplete until private transactions can move through the
real block path. Mempool privacy that stops at transaction relay is not a working
client.

- Block builders must have a specified path for selecting encrypted or shielded
  transactions, obtaining or verifying the required decryption/proof material,
  and constructing blocks that normal privacy-profile nodes can validate.
- Block propagation must carry whatever private transaction, proof, commitment,
  or decryption-share data is required for peers to import the block without
  relying on side channels or local-only state.
- Block validation and import must enforce the privacy fork rules directly. A
  private transaction that only works in a helper, script, RPC shortcut, or local
  test harness is not implemented.
- Reorg, rebroadcast, and recovery behavior must preserve privacy semantics.
  Retrying after missed inclusion must not reveal origin metadata, plaintext
  transaction contents, or key-release timing that the normal path hides.
- Compatibility fallback is allowed only as a liveness or emergency mechanism.
  It must be observable and must not be the primary path that makes tests pass.
- Long-running engineering sessions, branch size, or implementation difficulty
  are not scope boundaries. They do not justify carving the client into branded
  slices or merging a fallback-only path.

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
partitioning, or accumulator-backed scaling impossible to add.

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
  or non-production research tooling.
- Privacy1 fork gating is the only activation path for privacy consensus
  changes. No precompile, transaction type, or state-transition behavior should
  become active merely because an unrelated fork is active.
- Devnet trusted setup remains devnet-only. Any deterministic or insecure setup
  must be impossible to mistake for value-bearing network readiness.
- Placeholder gas constants must stay labelled as placeholders until benchmarked
  against realistic proof sizes and verification costs.
- Avoid competing roadmap documents. `shape.md` owns scope and client alignment;
  other docs may describe status, but they must not reclassify required client
  guarantees as separate tracks.
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
- Reject vague deferrals. If a required privacy guarantee is not wired into the
  client, say it is incomplete and document the privacy gap it creates.
- Reject fake completion. A helper, local harness, compatibility fallback,
  research package, or unconnected protocol stub is not a delivered client
  feature until the normal node path uses it and tests prove that path.

## Current Review

Review date: 2026-06-16.

Reviewed remote state after `git fetch --all --prune`:

- `origin/master` was at
  `bc02f2c1fecea76bc7924f9674b8b0063e83debd`.
- `origin/claude/go-ethereum-client-mods-8sz2dl` was at
  `4255ec109` and contained Dandelion++, threshold cryptography, encrypted
  envelope propagation, keyper registry, and DKG work.

The remote work branch is useful, but it is not implementation-complete against
this shape document and should not be treated as merge-ready without follow-up.

Implemented on that branch:

- `p2p/dandelion/dandelion.go` restores a Dandelion++ router package.
- `eth/handler.go`, `eth/handler_dandelion.go`, and the `dle` subprotocol wire
  Dandelion routing into the live transaction broadcast path.
- `eth/api_backend.go` marks RPC `SendTx` submissions as local-origin.
- Peer connect/disconnect refreshes the Dandelion eligible-peer set.
- Inbound transaction gossip marks hashes as fluffed and cancels local embargo
  state.
- An embargo loop diffuses expired stemmed transactions as a safety fallback.
- `eth/handler_encmempool.go` and the `enc` subprotocol propagate opaque
  encrypted envelopes between peers.
- `core/privacy/threshold`, `core/privacy/encmempool`, and
  `core/privacy/keyper` add primitive, buffer, registry, and DKG building blocks.

Blocking gaps against this shape:

- The branch still uses delivery labels in commit subjects and docs. Merge work
  must remove that framing and preserve this document's single-client target.
- Encrypted envelope propagation is not a private transaction path. It does not
  select encrypted transactions for blocks, release or verify decryption
  material, construct blocks, propagate block data, import blocks, or preserve
  privacy through reorg/rebroadcast behavior.
- Block propagation and inclusion are not covered by the privacy implementation
  tests. No test proves that a private transaction can enter the normal node,
  land in a block, propagate to another node, validate, update state, and retain
  the intended privacy guarantees.
- The registry and DKG work are not integrated into a live committee lifecycle.
  Tests exercise local primitives and in-memory state, not validator/keyper
  registration, share distribution, accountability, block import, or key-release
  timing.
- Source-of-funds compatibility proofs, prover orchestration, shielded-pool decoy
  scaling, and accountability surfaces remain design requirements, not client
  paths.

Test review:

- Keep the Dandelion router and handler tests that exercise origin stem routing,
  multi-hop relay, relay embargo, rebroadcast persistence, sync withholding,
  successor stability, and churn helpers. They are meaningful transaction
  propagation tests.
- Do not treat Dandelion tests as full client acceptance. They do not prove block
  construction, block propagation, block import, or private transaction inclusion.
- Keep threshold, envelope, registry, and DKG tests as primitive tests only.
  They are useful lower-level checks, but they are not proof that the client
  works.
- Rename or downgrade tests whose comments claim they prove encrypted-mempool
  privacy when they only check ciphertext buffering or byte containment. A test
  such as `TestNonIncludedStaysEncrypted` is acceptable as a buffer/unit test,
  but it is not a client privacy guarantee.
- `TestEncryptedMempoolPropagation` proves opaque envelope gossip across `enc`
  peers. It does not prove transaction validity, committee decryption, block
  selection, block propagation, block import, or reorg safety.
- Delete or rewrite any test that passes only because a helper, local harness,
  compatibility fallback, or protocol stub bypasses the normal node path.

Required before merge:

- Rebase the implementation branch onto current `origin/master` and preserve
  this document's latest requirements.
- Replace normal user opt-in flags with opinionated network/profile defaults.
  Any override must be clearly scoped as devnet, diagnostic, compatibility, or
  emergency tooling.
- Keep the explicit stem-relay signal or subprotocol so honest relays continue
  stem propagation beyond one hop, with fallback to ordinary gossip only for
  unsupported peers or emergency/liveness handling.
- Keep origin and relay routing semantics separated so originators never
  randomly fluff when a stem successor is available.
- Keep local-origin state persistent until fluff sighting, inclusion, or bounded
  expiry, and mark all local submission/resubmission paths.
- Keep at least two deterministic per-epoch successors and tests for churn
  resistance.
- Add production-path tests for private transaction block construction, block
  propagation, block import, reorg/rebroadcast behavior, missing or malformed
  decryption/proof material, and unsupported-peer fallback observability.

## Current Alignment Notes

- Confidential ETH state-transition work is part of the required client target.
- Stealth address support is part of the required client target.
- Dandelion++ network-origin privacy is part of the required client target and
  remains incomplete until wired into live propagation.
- Encrypted mempool work is part of the required client target. It may be
  implemented after Dandelion++ for engineering order, but it is not a separate
  delivery track or merge target. The target shape must account for modern
  threshold-encryption and batched-threshold-encryption research before the
  client is considered complete.
- Privacy precompiles must remain gated by the Privacy1 fork while this fork
  uses them as enabling infrastructure.
- Protocol-native shielded-pool integration must stay explicitly gated and
  devnet-scoped until production cryptographic setup exists.

## Done Means

No privacy feature is considered done because code exists. It is done only when:

- the implementation matches the required client target;
- the code is wired into the intended client path;
- unsupported paths fail closed or are explicitly labelled;
- tests cover the real path, not just isolated helpers;
- docs describe the actual guarantee, not the desired future guarantee.
