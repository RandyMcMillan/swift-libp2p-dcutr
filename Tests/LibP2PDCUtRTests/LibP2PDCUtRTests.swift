import Foundation
import XCTest
@testable import LibP2PDCUtR
import LibP2P

final class LibP2PDCUtRTests: XCTestCase {
    func testWireRoundTripsConnectMessage() throws {
        let original = HolePunch(
            type: .connect,
            obsAddrs: [
                try Multiaddr("/ip4/127.0.0.1/tcp/10000").binaryPacked(),
                try Multiaddr("/ip4/192.168.1.2/tcp/10001").binaryPacked(),
            ]
        )

        let decoded = try DCUtRWire.decode(DCUtRWire.encode(original))

        XCTAssertEqual(decoded.type, .connect)
        XCTAssertEqual(decoded.obsAddrs, original.obsAddrs)
    }

    func testWireRejectsMessagesLargerThanFourKiB() throws {
        let oversized = HolePunch(
            type: .connect,
            obsAddrs: [Data(repeating: 0, count: 4_097)]
        )

        XCTAssertThrowsError(try DCUtRWire.encode(oversized))

        var buffer = ByteBufferAllocator().buffer(capacity: 4_097)
        buffer.writeBytes([UInt8](repeating: 0, count: 4_097))

        XCTAssertThrowsError(try DCUtRWire.decode(buffer))
    }

    func testDeterministicPeerIDFromFixedMultihash() throws {
        let peer = try PeerID(fromHexID: "12200200bdb9f19d496460e6578874d5b34f614c52722b7af5bfc7d7d84396c48804")

        XCTAssertEqual(peer.b58String, "QmNUUBR4QUMRRjqkSVnh7L3TxKT5K2NZmNCv6JoZrv7hsq")
    }

    func testDialablePeerInfoFiltersCircuitAddresses() async throws {
        let peer = try PeerID()
        let peerInfo = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
                try Multiaddr("/ip4/127.0.0.1/tcp/10001/p2p-circuit"),
                try Multiaddr("/dns4/example.com/tcp/10002"),
            ]
        )

        let app = try await Application.make(.testing, peerID: .ephemeral)

        let dialable = DCUtRCoordinator(application: app).dialablePeerInfo(in: peerInfo)

        XCTAssertEqual(dialable.peer, peer)
        XCTAssertEqual(dialable.addresses, [try Multiaddr("/ip4/8.8.8.8/tcp/10000")])

        try await app.asyncShutdown()
    }

    @available(*, deprecated, message: "Transition to async tests")
    func testDialablePeerInfoFiltersCircuitAddresses_Deprecated() throws {
        let peer = try PeerID()
        let peerInfo = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
                try Multiaddr("/ip4/127.0.0.1/tcp/10001/p2p-circuit"),
                try Multiaddr("/dns4/example.com/tcp/10002"),
            ]
        )

        let app = Application(.testing)
        defer { app.shutdown() }

        let dialable = DCUtRCoordinator(application: app).dialablePeerInfo(in: peerInfo)

        XCTAssertEqual(dialable.peer, peer)
        XCTAssertEqual(dialable.addresses, [try Multiaddr("/ip4/8.8.8.8/tcp/10000")])
    }

    func testHasRelayReservationRequiresCircuitAddress() async throws {
        let app = try await Application.make(.testing, peerID: .ephemeral)

        let coordinator = DCUtRCoordinator(application: app)
        let peer = try PeerID()

        let noRelay = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
            ]
        )
        XCTAssertFalse(coordinator.hasRelayReservation(in: noRelay))

        let withRelay = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
                try Multiaddr("/ip4/127.0.0.1/tcp/10001/p2p-circuit"),
            ]
        )
        XCTAssertTrue(coordinator.hasRelayReservation(in: withRelay))

        try await app.asyncShutdown()
    }

    func testDialablePeerInfoKeepsPublicUdpQuicAddresses() async throws {
        let peer = try PeerID()
        let peerInfo = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/udp/4001/quic"),
                try Multiaddr("/ip4/8.8.8.8/udp/4002/quic-v1"),
                try Multiaddr("/ip4/127.0.0.1/udp/4001/quic"),
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
            ]
        )

        let app = try await Application.make(.testing, peerID: .ephemeral)

        let dialable = DCUtRCoordinator(application: app).dialablePeerInfo(in: peerInfo)

        XCTAssertEqual(dialable.peer, peer)
        XCTAssertEqual(
            Set(dialable.addresses),
            Set([
                try Multiaddr("/ip4/8.8.8.8/udp/4001/quic"),
                try Multiaddr("/ip4/8.8.8.8/udp/4002/quic-v1"),
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
            ])
        )

        try await app.asyncShutdown()
    }

    func testDialablePeerInfoSupportsMixedUdpAndTcpPeers() async throws {
        let app = try await Application.make(.testing, peerID: .ephemeral)
        let coordinator = DCUtRCoordinator(application: app)

        let udpPeer = try PeerID()
        let udpPeerInfo = PeerInfo(
            peer: udpPeer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/udp/4001/quic"),
                try Multiaddr("/ip4/8.8.8.8/udp/4002/quic-v1"),
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
            ]
        )

        let tcpPeer = try PeerID()
        let tcpPeerInfo = PeerInfo(
            peer: tcpPeer,
            addresses: [
                try Multiaddr("/ip4/1.1.1.1/tcp/10001"),
                try Multiaddr("/dns4/example.com/tcp/10002"),
            ]
        )

        XCTAssertEqual(
            Set(coordinator.dialablePeerInfo(in: udpPeerInfo).addresses),
            Set(udpPeerInfo.addresses)
        )
        XCTAssertEqual(
            Set(coordinator.dialablePeerInfo(in: tcpPeerInfo).addresses),
            Set([try Multiaddr("/ip4/1.1.1.1/tcp/10001")])
        )

        try await app.asyncShutdown()
    }

    func testDialablePeerInfoKeepsDnsUdpAddresses() async throws {
        let peer = try PeerID()
        let peerInfo = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/dns4/example.com/udp/4001/quic-v1"),
                try Multiaddr("/dns6/example.com/udp/4002/quic"),
                try Multiaddr("/dns4/example.com/tcp/10000"),
            ]
        )

        let app = try await Application.make(.testing, peerID: .ephemeral)

        let dialable = DCUtRCoordinator(application: app).dialablePeerInfo(in: peerInfo)

        XCTAssertEqual(dialable.peer, peer)
        XCTAssertEqual(
            Set(dialable.addresses),
            Set([
                try Multiaddr("/dns4/example.com/udp/4001/quic-v1"),
                try Multiaddr("/dns6/example.com/udp/4002/quic"),
            ])
        )

        try await app.asyncShutdown()
    }

    func testDialablePeerInfoRejectsBareUdpAddresses() async throws {
        let peer = try PeerID()
        let peerInfo = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/udp/4001"),
                try Multiaddr("/ip4/8.8.8.8/udp/4002/quic"),
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
            ]
        )

        let app = try await Application.make(.testing, peerID: .ephemeral)

        // Only QUIC-style UDP addrs should make it into DCUtR probing.
        let dialable = DCUtRCoordinator(application: app).dialablePeerInfo(in: peerInfo)

        XCTAssertEqual(
            Set(dialable.addresses),
            Set([
                try Multiaddr("/ip4/8.8.8.8/udp/4002/quic"),
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
            ])
        )

        try await app.asyncShutdown()
    }

    func testObservedAddressesExcludeInternalAddresses() async throws {
        let app = try await Application.make(.testing, peerID: .ephemeral)
        let coordinator = DCUtRCoordinator(application: app)

        let addresses = [
            try Multiaddr("/ip4/127.0.0.1/tcp/10000"),
            try Multiaddr("/ip4/8.8.8.8/tcp/10001"),
            try Multiaddr("/ip4/192.168.1.10/tcp/20000"),
            try Multiaddr("/ip4/1.1.1.1/tcp/20001"),
            try Multiaddr("/ip4/127.0.0.1/tcp/30000/p2p-circuit"),
        ]

        XCTAssertEqual(
            Set(coordinator.observedAddresses(from: addresses)),
            Set([
                try Multiaddr("/ip4/8.8.8.8/tcp/10001"),
                try Multiaddr("/ip4/1.1.1.1/tcp/20001"),
            ])
        )

        try await app.asyncShutdown()
    }

    func testObservedAddressesAreDeterministicallySorted() async throws {
        let app = try await Application.make(.testing, peerID: .ephemeral)
        let coordinator = DCUtRCoordinator(application: app)

        let addresses = [
            try Multiaddr("/ip4/1.1.1.1/tcp/20001"),
            try Multiaddr("/ip4/8.8.8.8/tcp/10001"),
            try Multiaddr("/ip4/1.1.1.1/tcp/20001"),
        ]

        XCTAssertEqual(
            coordinator.observedAddresses(from: addresses),
            [
                try Multiaddr("/ip4/1.1.1.1/tcp/20001"),
                try Multiaddr("/ip4/8.8.8.8/tcp/10001"),
            ]
        )

        try await app.asyncShutdown()
    }

    func testParsePeerInfoRejectsMaliciousAndCircuitAddresses() async throws {
        let app = try await Application.make(.testing, peerID: .ephemeral)
        let coordinator = DCUtRCoordinator(application: app)
        let peer = try PeerID()

        let message = HolePunch(
            type: .connect,
            obsAddrs: [
                Data([0xff, 0x00, 0x01]),
                try Multiaddr("/ip4/192.168.1.1/tcp/10002").binaryPacked(),
                try Multiaddr("/ip4/8.8.8.8/tcp/10000").binaryPacked(),
                try Multiaddr("/ip4/127.0.0.1/tcp/10001/p2p-circuit").binaryPacked(),
            ]
        )

        let parsed = try coordinator.parsePeerInfo(from: message, fallbackPeer: peer)

        XCTAssertEqual(parsed.peer, peer)
        XCTAssertEqual(parsed.addresses, [try Multiaddr("/ip4/8.8.8.8/tcp/10000")])

        try await app.asyncShutdown()
    }

    func testInvalidatingAttemptMakesOldGenerationStale() async throws {
        let app = try await Application.make(.testing, peerID: .ephemeral)
        let coordinator = DCUtRCoordinator(application: app)
        let peer = try PeerID()

        let initial = coordinator.currentAttemptGeneration(for: peer)
        coordinator.invalidateAttempt(for: peer)

        XCTAssertEqual(coordinator.currentAttemptGeneration(for: peer), initial + 1)
        XCTAssertFalse(coordinator.currentAttemptGeneration(for: peer) == initial)

        try await app.asyncShutdown()
    }

    func testHandshakeTimeoutVersionAdvancesMonotonically() async throws {
        let app = try await Application.make(.testing, peerID: .ephemeral)
        let coordinator = DCUtRCoordinator(application: app)

        XCTAssertEqual(coordinator.nextHandshakeTimeoutVersion(after: nil), 1)
        XCTAssertEqual(coordinator.nextHandshakeTimeoutVersion(after: 1), 2)
        XCTAssertEqual(coordinator.nextHandshakeTimeoutVersion(after: 7), 8)

        try await app.asyncShutdown()
    }

    func testInvalidatingAttemptAdvancesRetryGeneration() async throws {
        let app = try await Application.make(.testing, peerID: .ephemeral)
        let coordinator = DCUtRCoordinator(application: app)
        let peer = try PeerID()

        let initial = coordinator.currentAttemptGeneration(for: peer)
        coordinator.invalidateAttempt(for: peer)

        XCTAssertEqual(coordinator.currentAttemptGeneration(for: peer), initial + 1)
        XCTAssertNotEqual(coordinator.currentAttemptGeneration(for: peer), initial)

        try await app.asyncShutdown()
    }

    @available(*, deprecated, message: "Transition to async tests")
    func testHasRelayReservationRequiresCircuitAddress_Deprecated() throws {
        let app = Application(.testing)
        defer { app.shutdown() }

        let coordinator = DCUtRCoordinator(application: app)
        let peer = try PeerID()

        let noRelay = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
            ]
        )
        XCTAssertFalse(coordinator.hasRelayReservation(in: noRelay))

        let withRelay = PeerInfo(
            peer: peer,
            addresses: [
                try Multiaddr("/ip4/8.8.8.8/tcp/10000"),
                try Multiaddr("/ip4/127.0.0.1/tcp/10001/p2p-circuit"),
            ]
        )
        XCTAssertTrue(coordinator.hasRelayReservation(in: withRelay))
    }
}
