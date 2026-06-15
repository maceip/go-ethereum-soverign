# Sovereign Privacy Shape

This document is the alignment source for this fork. The attached roadmap,
*"Ethereum Privacy: The Road to Self-Sovereignty"*, is the source of truth for
scope and phase placement. Existing implementation notes must be read through
this document when there is any tension.

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
- The implementation is feature-gated and tunable without changing consensus.
- Multi-peer tests cover origin-obfuscation behavior; unit tests for a router
  alone do not satisfy the requirement.

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
  Dandelion++ must be behind an explicit privacy/network flag with parameters
  for enablement, stem probability, epoch duration, embargo base delay, and
  embargo jitter.
- Metrics and logs:
  track stem sends, fluff broadcasts, embargo expiries, peer-selection fallback,
  and disabled-path fallback.
- Tests and simulations:
  include a multi-node propagation harness with adversarial observers, plus tests
  for local submission, remote relay, epoch rotation, embargo expiry, peer loss,
  and rebroadcast/reorg behavior.

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
- Do not ship "privacy" APIs that imply guarantees the client does not provide.
  If a feature is a helper, say helper. If it is incomplete, say incomplete.
- Keep protocol changes minimal and explicit. New dependencies, precompiles,
  transaction types, reserved addresses, and RPC methods must each map to a
  roadmap target and a testable acceptance criterion.
- Scope wallet conveniences separately from consensus. RPC helpers may make
  wallet integration easier, but they do not substitute for protocol or network
  privacy.
- Reject vague deferrals. If the attached roadmap places an item in Phase 1,
  this fork must not move it to Phase 2 without explicitly documenting the
  reason and the privacy gap it creates.

## Current Alignment Notes

- Confidential ETH state transition work is Phase 1.
- Stealth address support is Phase 1.
- Dandelion++ network-origin privacy is Phase 1 and currently incomplete until
  wired into live propagation.
- Encrypted mempool work is also Phase 1, but it can be staged after Dandelion++
  if the client needs an incremental network-privacy milestone.
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
