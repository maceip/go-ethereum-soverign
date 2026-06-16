# Sovereign Privacy: go-ethereum implementation

This fork begins implementing the client-side building blocks described in
**"Ethereum Privacy: The Road to Self-Sovereignty"** by pcaversaccio
([discussion](https://ethresear.ch/t/ethereum-privacy-the-road-to-self-sovereignty/22115)).

The published roadmap uses phase labels to organise multi-year, multi-team
protocol work. In this fork those labels are source-context only: per `shape.md`
there is **one client target**, not a sequence of internal phases, demos, betas, or
slices. The privacy guarantees are either wired into the real client paths,
working out of the box on the privacy network profile and covered by tests, or
described plainly as incomplete. This document describes the status of that one
client target; `shape.md` is authoritative for scope.

## What is implemented

| Roadmap item | Phase | Where |
| --- | --- | --- |
| **Sealed amounts** — additively-homomorphic Pedersen commitments to hide values while proving balance conservation | 1 | [`core/privacy/pedersen.go`](core/privacy/pedersen.go) |
| **Native stealth addresses** (EIP-5564) — unlinkable one-time recipient addresses with view-tag scanning | 1 | [`core/privacy/stealth.go`](core/privacy/stealth.go) |
| **UX & wallet integration** — `privacy` JSON-RPC namespace (pool introspection, shield builder, stealth/commitment helpers) | 1 | [`eth/privacy_api.go`](eth/privacy_api.go) |
| **Privacy precompiles** — `PEDERSEN_COMMIT` (`0x12`), `PEDERSEN_ADD` (`0x13`), `PLONK_VERIFY` (`0x14`), gated by the Privacy1 fork | 3 | [`core/vm/contracts_privacy.go`](core/vm/contracts_privacy.go) |
| **Shielded-pool primitives** — incremental Merkle commitment tree + nullifier set for double-spend prevention | 2 / 4 | [`core/privacy/shieldedpool.go`](core/privacy/shieldedpool.go) |
| **Network-origin privacy** — Dandelion++ stem/fluff transaction propagation, wired into the live broadcast path with embargo failsafe | 1 | [`p2p/dandelion/dandelion.go`](p2p/dandelion/dandelion.go), [`eth/handler_dandelion.go`](eth/handler_dandelion.go) |

> Network-origin privacy (Dandelion++) is a **core client requirement** and is
> **wired into the live transaction-propagation path** as a **multi-hop stem**:
> locally-originated transactions enter stem routing by default and are relayed
> over a dedicated [`dle`](eth/protocols/dandelion) sub-protocol that lets honest
> relays continue the stem, with an embargo failsafe and ordinary gossip as the
> safety fallback. The originator never diffuses by chance, local-origin status
> persists across re-broadcasts (and such transactions are withheld from initial
> mempool sync until they fluff), multiple epoch-stable successors are used, and
> every stemming node arms its own embargo. Stem-successor selection is hardened
> against eclipse / connection-reset attacks (stability gating, subnet diversity,
> outbound preference, churn monitoring). Per the **Opinionated Privacy Defaults**
> in [`shape.md`](shape.md), it is **active by default on the privacy network
> profile** (any network that activates the Privacy1 fork) — not a user opt-in;
> the only disable path is a labelled emergency/diagnostic override
> (`--dandelion.disable`). It changes no consensus rules.

## Design notes

- **Pedersen commitments** are built over the existing bn256 G1 group used by the
  EIP-196/197 precompiles, so commitments share the EVM-native 64-byte point
  encoding and the `PEDERSEN_ADD` result is directly consumable by other bn256
  precompiles. The second generator `H` is derived nothing-up-my-sleeve by hashing
  the canonical encoding of `G` into the group.
- The privacy precompiles are gated by the **Privacy1 fork** (`rules.IsPrivacy1`),
  overlaid on the active base fork's precompile set. A chain that has not activated
  Privacy1 is byte-for-byte unaffected.
- The `privacy` RPC namespace never holds private keys and never signs:
  `BuildShield` returns an *unsigned* transaction for the caller to sign and submit.

## Future roadmap beyond the client target

These are out of scope for the current privacy client target and are recorded only
as roadmap context (per `shape.md`, not deferred tracks of this work): confidential
ERC-20/721 token standards, zkEVM private execution, protocol-native shielded pools
and fair ordering, and post-quantum migration. The primitives and consensus
machinery in this client are the substrate they would build on.

## Tests

```
go test ./core/privacy/... ./core/vm/ -run 'Test'
go test ./eth/ -run 'TestPrivacyAPI'
```
