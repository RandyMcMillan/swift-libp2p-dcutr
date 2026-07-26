# swift-libp2p-dcutr

`LibP2PDCUtR` is a Swift package that implements libp2p's **Direct Connection Upgrade through Relay (DCUtR)** protocol for the `swift-libp2p` stack.

It follows the DCUtR spec closely: peers exchange `CONNECT` and `SYNC` messages over a relay stream, share observed addresses from identify, then attempt to upgrade to a direct TCP or QUIC-style connection.

- [DCUtR spec](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md)
- [Peer-to-Peer Communication Across Network Address Translators](https://pdos.csail.mit.edu/papers/p2pnat.pdf)
- [RFC 5245: Interactive Connectivity Establishment (ICE)](https://datatracker.ietf.org/doc/html/rfc5245)

## What it does

- Listens for relay-connected peers and starts DCUtR when both sides are identified.
- Encodes/decodes `HolePunch` protobuf messages with varint-prefixed framing.
- Enforces the spec's 4 KiB RPC payload limit.
- Filters internal and relay-circuit addresses out of upgrade candidates.
- Supports direct dialing for TCP and speculative UDP burst probing for QUIC-style addresses.
- Retries failed upgrades with bounded attempt counts and handshake timeouts.
- Includes compatibility tests for both async and deprecated app initializers.

## Protocol summary

DCUtR works like this:

1. A relay connection is established between two peers.
2. The inbound peer checks the remote peer's advertised addresses.
3. If a direct address is available, it tries a unilateral upgrade.
4. Otherwise it opens a `/libp2p/dcutr/1.0.0` stream and sends `CONNECT`.
5. The remote side replies with `CONNECT`, then the initiator sends `SYNC`.
6. Both sides attempt a simultaneous direct connection.
7. Once a direct connection succeeds, relay connections are closed after a grace period.

For QUIC-style addresses, the implementation sends repeated random UDP datagrams at randomized intervals between 10 and 200 ms, matching the intent of the spec.

## Current hardening

The implementation includes a few defensive checks to reduce low-and-slow or abuse cases:

- rejects oversized RPCs before decode
- ignores malformed observed addresses
- drops internal and `p2p-circuit` addresses from upgrade state
- deduplicates and sorts observed address lists
- applies a short handshake timeout to stalled upgrade streams
- limits retries to the spec's retry budget
- rate-limits speculative UDP retry attempts

## Package layout

- `Sources/LibP2PDCUtR/LibP2PDCUtR.swift` — core protocol logic and coordinator
- `Sources/LibP2PDCUtR/Protobuf/HolePunch.proto` — protobuf schema
- `Tests/LibP2PDCUtRTests/LibP2PDCUtRTests.swift` — wire, filtering, retry, and hardening tests

## Dependencies

This package depends on:

- `swift-libp2p`
- `swift-nio`
- `swift-protobuf`

## Requirements

- Swift 6.0+
- macOS 10.15+ or iOS 13+

## Build

```bash
swift build
```

## Test

```bash
swift test
```

## Usage

Install the coordinator into your libp2p application and let it attach the DCUtR stream handler and event listeners.

```swift
let app = try await Application.make(.testing, peerID: .ephemeral)
let coordinator = DCUtRCoordinator(application: app)
coordinator.install()
```

The coordinator will:

- watch relay connections
- wait for identify data
- decide whether to attempt direct TCP or UDP/QUIC punching
- coordinate `CONNECT`/`SYNC` exchange over the DCUtR stream

## Test compatibility

The test suite keeps both:

- async application setup/shutdown tests
- deprecated initializer-based compatibility tests

That preserves coverage for newer APIs and older call sites.

## Notes

- Bare `/udp/...` addrs are not treated as DCUtR-punchable; only QUIC-style UDP addrs are used for probing.
- DNS-based UDP addresses are resolved for speculative probing.
- The implementation prefers TCP direct dials before speculative UDP probing when both are available.
- CONNECT payload ordering is normalized so tests and wire behavior stay deterministic.
