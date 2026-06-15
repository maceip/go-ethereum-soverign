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
  an eligible stem peer. The originator must **never** apply the stem/fluff coin
  at its own hop: a local transaction either stems (eligible successor exists) or
  falls back to diffusion only because no successor exists — it must not diffuse
  directly from the origin by random chance. See Design Correction 1.
- The implementation preserves phase semantics for local, stem-relayed, and
  fluff/diffusion transactions. "Stem-relayed" requires that an honest relay can
  recognise a transaction that arrived in the stem phase and continue stemming it,
  rather than immediately diffusing. A stem that cannot continue past the first
  hop does not satisfy this criterion. See Design Correction 2.
- Local-origin status must persist across re-broadcasts: a transaction known to
  originate locally stays stem-eligible until it is observed fluffing or is
  included, not only on its first broadcast. See Design Correction 3.
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

## Dandelion++ Design Corrections

The first Dandelion++ implementation is wired into the live broadcast path and
passes its origin-obfuscation tests, but a design review identified weaknesses
that materially weaken the anonymity it provides. These corrections are
binding; where a correction conflicts with an earlier acceptance criterion or
touchpoint, the correction wins. Until a correction lands, its gap must be stated
plainly in the status docs rather than papered over.

### Correction 1 — The originator must not fluff at its own hop

Symptom: the stem/fluff coin is evaluated at every hop including hop 0, so with
probability `1 - StemProbability` a locally-originated transaction is diffused
directly from the origin. The router comment claims locals "always start in the
stem phase," but the code does not implement that, and the router has no
origin-versus-relay distinction at all.

Required change: the routing decision must know whether the local node is the
originator or a relay. At the originator the transaction unconditionally enters
the stem phase whenever an eligible successor exists; the fluff coin applies only
at relay hops. Diffusion at the origin is permitted only as the no-successor
fallback.

Acceptance: a test that, across many trials (or with forced randomness), a local
transaction with an eligible successor is never diffused directly from the origin.

### Correction 2 — The stem must continue across honest relays

Symptom: a stemmed transaction is relayed as an ordinary direct `Transactions`
broadcast, indistinguishable on the wire from a normal square-root broadcast. The
receiving relay cannot tell the transaction is in the stem phase, so it diffuses
immediately. The effective stem length is therefore one hop: the chosen successor
learns the origin exactly, and a network observer sees the fluff begin at a node
directly adjacent to the origin. This is single-hop origin obfuscation, not
Dandelion++.

Required change: introduce an explicit, feature-gated stem-relay signal so an
honest relay recognises a stem-phase transaction and continues it (forwarding to
its own successor and arming its own embargo) instead of fluffing. Acceptable
shapes are a dedicated message in a `dandelion` sub-protocol, or a gated
extension of the eth transaction-relay path. The signal must degrade to normal
gossip against peers that do not advertise support, must remain non-consensus,
and must not make stemmed transactions linkable across hops beyond what
Dandelion++ already implies. If multi-hop stem is deliberately deferred, the fork
must state that network-origin privacy is single-hop only and document the
reduced guarantee — it must not be described as full Dandelion++.

Acceptance: a multi-node test in which a transaction traverses at least two
honest stem relays before fluffing, the fluff origin is at least two hops from
the true origin, and a peer lacking the stem signal falls back to gossip.

### Correction 3 — Local-origin status must survive re-broadcast and cover all local paths

Symptom: local-origin tracking is consume-once and is fed only by the RPC
`SendTx` path. The transaction pool periodically re-broadcasts still-pending
local transactions; after the first broadcast the origin record is gone, so every
subsequent re-broadcast diffuses from the origin, eventually revealing it.
Miner-local, journal-resurrected, and locally-resubmitted transactions are never
marked at all.

Required change: a transaction known to be local must remain stem-eligible until
it is observed fluffing or is included in a block, not merely on first broadcast.
Eviction is driven by fluff sighting, inclusion, or a TTL bound — not by single
consumption. All local submission paths (RPC, local wallet, miner, local-tx
journal/resubmission) must mark origin.

Acceptance: a test that a local transaction re-broadcast N times stems on each
re-broadcast until a fluff sighting, and never diffuses directly from the origin.

### Correction 4 — Use at least two stem successors with deterministic per-epoch selection

Symptom: a single per-epoch successor routes every local transaction of the epoch
through one neighbour. A single malicious or failed successor can observe (and
attempt to black-hole) all of the node's local traffic for the whole epoch, and
the successor is silently re-randomised on any mid-epoch peer churn.

Required change: select a small fixed set (at least two) of stem successors per
epoch and choose among them per transaction, for robustness against a single bad
or dropped successor. Make per-epoch selection a deterministic pseudo-random
function of `(epoch, self, eligible peers)` so it is stable within an epoch and
not trivially churnable; re-select only when a chosen successor actually leaves.

Acceptance: tests for at-least-two-successor selection, stability within an epoch
under unrelated peer churn, and re-selection only on successor loss.

### Correction 5 — Every stemming node arms its own embargo

Symptom: the embargo failsafe is armed only by the originator. Once Correction 2
enables multi-hop stems, an honest relay that forwards a stemmed transaction has
no failsafe of its own, so a black hole placed downstream of a relay is recovered
only if the origin's embargo happens to fire.

Required change: every node that forwards a transaction in the stem phase arms an
embargo for that hash and diffuses it on expiry, exactly as the originator does.
(Depends on Correction 2.)

Acceptance: a multi-hop test in which a black hole placed after the first relay is
recovered by that relay's own embargo.

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
- Dandelion++ network-origin privacy is Phase 1 and is now wired into live
  propagation, but the initial design is single-hop and leaks the origin in
  several cases (originator fluff, re-broadcast, non-RPC local paths). Until the
  Design Corrections land, the guarantee it provides is "single-hop origin
  obfuscation," not full Dandelion++, and the status docs must say so.
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
