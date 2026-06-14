# Sovereign Privacy: go-ethereum implementation

This fork begins implementing the client-side building blocks described in
**"Ethereum Privacy: The Road to Self-Sovereignty"** by pcaversaccio
([discussion](https://ethresear.ch/t/ethereum-privacy-the-road-to-self-sovereignty/22115)).

The full roadmap spans five phases of multi-year, multi-team protocol work. This
changeset delivers a coherent, compiling, and tested vertical slice of the items
that live naturally in the execution client, with each component built as reusable
infrastructure the later phases compose on top of.

## What is implemented

| Roadmap item | Phase | Where |
| --- | --- | --- |
| **Sealed amounts** — additively-homomorphic Pedersen commitments to hide values while proving balance conservation | 1 | [`core/privacy/pedersen.go`](core/privacy/pedersen.go) |
| **Native stealth addresses** (EIP-5564) — unlinkable one-time recipient addresses with view-tag scanning | 1 | [`core/privacy/stealth.go`](core/privacy/stealth.go) |
| **Network-level anonymity via Dandelion++** — stem/fluff transaction propagation with per-epoch successor rotation and embargo failsafe | 1 | [`p2p/dandelion/dandelion.go`](p2p/dandelion/dandelion.go) |
| **UX & wallet integration** — `privacy` JSON-RPC namespace for stealth-address generation/detection and commitments | 1 | [`eth/privacy_api.go`](eth/privacy_api.go) |
| **Privacy precompiles** — `PEDERSEN_COMMIT` (`0x12`) and `PEDERSEN_ADD` (`0x13`) to make confidential-value bookkeeping economical on L1 | 3 | [`core/vm/contracts_privacy.go`](core/vm/contracts_privacy.go) |
| **Shielded-pool primitives** — incremental Merkle commitment tree + nullifier set for double-spend prevention | 2 / 4 | [`core/privacy/shieldedpool.go`](core/privacy/shieldedpool.go) |

## Design notes

- **Pedersen commitments** are built over the existing bn256 G1 group used by the
  EIP-196/197 precompiles, so commitments share the EVM-native 64-byte point
  encoding and the `PEDERSEN_ADD` result is directly consumable by other bn256
  precompiles. The second generator `H` is derived nothing-up-my-sleeve by hashing
  the canonical encoding of `G` into the group.
- The two precompiles are registered only in the **Osaka** precompile set, so
  pre-Osaka consensus behaviour is unchanged. Generic Groth16/PlonK verification is
  already available through the existing bn256 pairing precompile (`0x08`); the new
  precompiles add the fused commitment + homomorphic-add operations a
  confidential-value scheme needs and which are expensive to express in EVM
  bytecode.
- **Dandelion++** is implemented as transport-agnostic routing logic with an
  injectable clock and RNG so it is deterministically testable. It is intentionally
  *not* wired into default transaction propagation, because changing the gossip
  path is a consensus-adjacent networking change that needs its own review and an
  opt-in flag; the `Router` exposes exactly the `Relay`/`Broadcast`/embargo hooks a
  caller needs to integrate it into `eth/handler.go`.
- The `privacy` RPC namespace is **stateless** — it never holds keys, touches chain
  state, or signs — making it safe for wallet tooling to consume.

## Not yet implemented (later roadmap phases)

These require protocol-level consensus changes and/or production zk circuits that
are out of scope for this changeset, but the primitives above are the substrate
they build on: a native confidential-ETH transaction type (Phase 1), an encrypted
threshold-decryption mempool (Phase 1), confidential ERC-20/721 standards
(Phase 2), zkEVM execution (Phase 3/5), protocol-native shielded pools and fair
ordering (Phase 4), and post-quantum migration (Phase 5).

## Tests

```
go test ./core/privacy/ ./p2p/dandelion/ ./core/vm/ -run 'Test'
go test ./eth/ -run 'TestPrivacyAPI'
```
