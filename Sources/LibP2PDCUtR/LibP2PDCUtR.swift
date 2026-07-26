import Foundation
import LibP2P
import NIO
import SwiftProtobuf

enum DCUtRWire {
    static let protocolID = "/libp2p/dcutr/1.0.0"
    // The spec requires varint-framed protobuf RPCs and recommends refusing messages > 4 KiB.
    static let maxMessageSize = 4 * 1024

    static func encode(_ message: HolePunch) throws -> ByteBuffer {
        let data = try message.serializedData()
        guard data.count <= maxMessageSize else {
            throw DCUtRError.messageTooLarge
        }
        var buffer = ByteBufferAllocator().buffer(capacity: data.count)
        buffer.writeBytes(data)
        return buffer
    }

    static func decode(_ buffer: ByteBuffer) throws -> HolePunch {
        guard buffer.readableBytes <= maxMessageSize else {
            throw DCUtRError.messageTooLarge
        }
        return try HolePunch(serializedBytes: Data(buffer.readableBytesView))
    }
}

enum DCUtRError: Error {
    case messageTooLarge
}

final class DCUtRCoordinator: @unchecked Sendable {
    struct Attempt {
        var relayConnection: Connection?
        var remotePeerInfo: PeerInfo?
        var connectSentAt: Date?
        var connectReceivedAt: Date?
        var generation: Int = 0
        var retryCount: Int = 0
        var retryScheduled: Bool = false
    }

    private let application: Application
    private let queue = DispatchQueue(label: "LibP2PDCUtR.attempts")
    private var attempts: [String: Attempt] = [:]
    private let maxRetries: Int = 3
    private let retryDelay: TimeAmount = .seconds(1)
    private let relayCloseDelay: TimeAmount = .seconds(2)

    init(application: Application) {
        self.application = application
    }

    func install() {
        // Hook the relay, identify, and dcutr stream handlers so the upgrade flow can follow the spec.
        self.application.events.on(self, event: .connected(self.onConnected(_:)))
        self.application.events.on(self, event: .disconnected(self.onDisconnected(_:_:)))
        self.application.events.on(self, event: .identifiedPeer(self.onIdentifiedPeer(_:)))
        self.application.group("libp2p") { libp2p in
            libp2p.group("dcutr", handlers: [.varIntLengthPrefixed]) { dcutr in
                dcutr.on("1.0.0", handlers: [.varIntLengthPrefixed]) { req in
                    try await self.handle(req)
                }
            }
        }
        self.application.logger.notice("Installed DCUtR hole punching support")
    }

    private func isRelayConnection(_ connection: Connection) -> Bool {
        guard let addr = connection.remoteAddr else { return false }
        return addr.protocols().contains(where: { $0 == .p2p_circuit })
    }

    private func attempt(for peer: PeerID) -> Attempt {
        self.queue.sync { self.attempts[peer.b58String] ?? Attempt() }
    }

    private func setAttempt(_ attempt: Attempt, for peer: PeerID) {
        self.queue.sync { self.attempts[peer.b58String] = attempt }
    }

    private func clearAttempt(for peer: PeerID) {
        self.queue.sync {
            let current = self.attempts[peer.b58String] ?? Attempt()
            self.attempts[peer.b58String] = Attempt(generation: current.generation + 1)
        }
    }

    private func resetHandshake(for peer: PeerID) {
        var attempt = self.attempt(for: peer)
        attempt.connectSentAt = nil
        attempt.connectReceivedAt = nil
        attempt.retryScheduled = false
        attempt.generation += 1
        self.setAttempt(attempt, for: peer)
    }

    private func mergePeerInfo(_ lhs: PeerInfo?, with rhs: PeerInfo) -> PeerInfo {
        guard let lhs else { return rhs }
        let addresses = Array(Set(lhs.addresses).union(rhs.addresses))
        return PeerInfo(peer: rhs.peer, addresses: addresses)
    }

    func hasRelayReservation(in peerInfo: PeerInfo) -> Bool {
        peerInfo.addresses.contains { $0.protocols().contains(.p2p_circuit) }
    }

    private func isDialableAddress(_ address: Multiaddr) -> Bool {
        guard !address.isInternalAddress else { return false }
        guard !address.protocols().contains(.p2p_circuit) else { return false }
        return (try? self.application.transports.findBest(forMultiaddr: address)) != nil
    }

    private func dialableAddresses(in peerInfo: PeerInfo) -> [Multiaddr] {
        peerInfo.addresses.filter { self.isDialableAddress($0) }
    }

    func dialablePeerInfo(in peerInfo: PeerInfo) -> PeerInfo {
        PeerInfo(peer: peerInfo.peer, addresses: self.dialableAddresses(in: peerInfo))
    }

    private func directDialAddresses(for peerInfo: PeerInfo) -> [Multiaddr] {
        self.dialableAddresses(in: peerInfo).map { address in
            if address.getPeerIDString() != nil {
                return address
            }
            return (try? address.encapsulate(proto: .p2p, address: peerInfo.peer.b58String)) ?? address
        }
    }

    private func isQuicLikeAddress(_ address: Multiaddr) -> Bool {
        let protocols = address.protocols()
        return protocols.contains(.udp) || protocols.contains(.quic)
    }

    private func scheduleSpeculativeQuicDial(
        peer: PeerID,
        relayConnection: Connection?,
        address: Multiaddr,
        generation: Int,
        remainingAttempts: Int,
        onExhausted: @escaping @Sendable () -> Void
    ) {
        guard remainingAttempts > 0 else {
            onExhausted()
            return
        }
        let delayMs = Int64.random(in: 10...200)
        self.application.eventLoopGroup.any().scheduleTask(in: .milliseconds(delayMs)) {
            guard self.attempt(for: peer).generation == generation else { return }
            do {
                // The spec asks for repeated UDP bursts; here the QUIC transport emits the actual packets.
                try self.application.newStream(to: address, forProtocol: DCUtRWire.protocolID)
                self.cancelOutstandingConnections(for: peer, relayConnection: relayConnection)
            } catch {
                self.scheduleSpeculativeQuicDial(
                    peer: peer,
                    relayConnection: relayConnection,
                    address: address,
                    generation: generation,
                    remainingAttempts: remainingAttempts - 1,
                    onExhausted: onExhausted
                )
            }
        }
    }

    private func refreshPeerInfo(for peer: PeerID) {
        self.application.peers.getPeerInfo(byID: peer.b58String, on: self.application.eventLoopGroup.any()).whenSuccess { peerInfo in
            self.queue.sync {
                let merged = self.mergePeerInfo(self.attempts[peer.b58String]?.remotePeerInfo, with: peerInfo)
                var attempt = self.attempts[peer.b58String] ?? Attempt()
                attempt.remotePeerInfo = merged
                self.attempts[peer.b58String] = attempt
            }
            self.startPunchIfReady(for: peer)
        }
    }

    private func startPunchIfReady(for peer: PeerID) {
        let eventLoop = self.application.eventLoopGroup.any()
        self.application.peers.getPeerInfo(byID: peer.b58String, on: eventLoop).whenSuccess { peerInfo in
            guard self.hasRelayReservation(in: peerInfo) else { return }

            var relayConnection: Connection?
            self.queue.sync {
                guard
                    let attempt = self.attempts[peer.b58String],
                    let connection = attempt.relayConnection
                else {
                    return
                }
                relayConnection = connection
            }

            guard let relayConnection else { return }
            // Spec step 1: if we already know a direct address, try the unilateral upgrade first.
            let directAddresses = self.directDialAddresses(for: peerInfo)
            if !directAddresses.isEmpty {
                if self.attemptDirectUpgrade(for: peer, relayConnection: relayConnection, remoteInfo: peerInfo) {
                    return
                }
            }
            // Otherwise fall back to the relay-mediated CONNECT/SYNC exchange.
            self.initiatePunch(for: peer, relayConnection: relayConnection)
        }
    }

    private func registerRelayConnection(_ connection: Connection, for peer: PeerID) {
        var attempt = self.attempt(for: peer)
        guard attempt.relayConnection == nil else { return }
        attempt.relayConnection = connection
        self.setAttempt(attempt, for: peer)
    }

    private func localObservedAddresses() -> [Multiaddr] {
        let addresses = self.application.peerInfo.addresses + self.application.listenAddresses
        return Array(Set(addresses.filter { !($0.protocols().contains(.p2p_circuit)) }))
    }

    private func makePayload(type: HolePunch.Kind) throws -> ByteBuffer {
        let message = HolePunch(type: type, obsAddrs: try self.localObservedAddresses().map { try $0.binaryPacked() })
        return try DCUtRWire.encode(message)
    }

    private func parsePeerInfo(from message: HolePunch, fallbackPeer: PeerID?) throws -> PeerInfo {
        var addrs: [Multiaddr] = []
        for raw in message.obsAddrs {
            do {
                let ma = try Multiaddr(raw)
                if ma.protocols().contains(where: { $0 == .p2p_circuit }) { continue }
                addrs.append(ma)
            } catch {
                self.application.logger.warning("Skipping invalid hole punch address: \(error)")
            }
        }
        let peer = fallbackPeer ?? self.application.peerID
        return PeerInfo(peer: peer, addresses: addrs)
    }

    private func initiatePunch(for peer: PeerID, relayConnection: Connection) {
        var attempt = self.attempt(for: peer)
        attempt.relayConnection = relayConnection
        guard attempt.connectSentAt == nil else { return }
        attempt.connectSentAt = Date()
        attempt.connectReceivedAt = nil
        self.setAttempt(attempt, for: peer)
        do {
            try self.application.newStream(to: peer, forProtocol: DCUtRWire.protocolID)
        } catch {
            self.application.logger.error("DCUtR: failed to open connect stream to \(peer.b58String): \(error)")
            self.scheduleRetry(for: peer)
        }
    }

    private func attemptDirectUpgrade(for peer: PeerID, relayConnection: Connection, remoteInfo: PeerInfo) -> Bool {
        let directAddresses = self.directDialAddresses(for: remoteInfo)
        guard !directAddresses.isEmpty else { return false }

        for address in directAddresses {
            if self.isQuicLikeAddress(address) {
                let generation = self.attempt(for: peer).generation
                self.scheduleSpeculativeQuicDial(
                    peer: peer,
                    relayConnection: relayConnection,
                    address: address,
                    generation: generation,
                    remainingAttempts: 12,
                    onExhausted: { self.initiatePunch(for: peer, relayConnection: relayConnection) }
                )
                return true
            }

            do {
                // Spec step 6: if a direct connection wins, keep the relay alive briefly and then close it.
                try self.application.newStream(to: address, forProtocol: DCUtRWire.protocolID)
                self.cancelOutstandingConnections(for: peer, relayConnection: relayConnection)
                return true
            } catch {
                self.application.logger.debug("DCUtR: direct upgrade dial failed for \(address): \(error)")
            }
        }

        return false
    }

    private func cancelOutstandingConnections(for peer: PeerID, relayConnection: Connection?) {
        let loop = self.application.eventLoopGroup.any()
        self.application.connections.getConnectionsToPeer(peer: peer, on: loop).whenSuccess { connections in
            for connection in connections {
                guard connection.remoteAddr?.protocols().contains(.p2p_circuit) == true else { continue }
                connection.close().whenComplete { _ in }
            }
        }
        if let relayConnection {
            self.scheduleRelayClose(for: peer, relayConnection: relayConnection)
        }
        self.clearAttempt(for: peer)
    }

    private func scheduleRelayClose(for peer: PeerID, relayConnection: Connection) {
        self.application.eventLoopGroup.any().scheduleTask(in: self.relayCloseDelay) {
            relayConnection.close().whenComplete { _ in }
            self.clearAttempt(for: peer)
        }
    }

    private func scheduleRetry(for peer: PeerID) {
        var attempt = self.attempt(for: peer)
        guard attempt.retryCount < (self.maxRetries - 1), attempt.retryScheduled == false else { return }
        attempt.retryCount += 1
        attempt.retryScheduled = true
        attempt.connectSentAt = nil
        attempt.connectReceivedAt = nil
        attempt.generation += 1
        let generation = attempt.generation
        self.setAttempt(attempt, for: peer)

        self.application.eventLoopGroup.any().scheduleTask(in: self.retryDelay) {
            guard self.attempt(for: peer).generation == generation else { return }
            var attempt = self.attempt(for: peer)
            attempt.retryScheduled = false
            self.setAttempt(attempt, for: peer)
            self.startPunchIfReady(for: peer)
        }
    }

    private func dialDirect(for peer: PeerID, remoteInfo: PeerInfo) -> Bool {
        let directAddresses = self.directDialAddresses(for: remoteInfo)
        guard !directAddresses.isEmpty else { return false }

        for address in directAddresses {
            do {
                try self.application.newStream(to: address, forProtocol: DCUtRWire.protocolID)
                self.cancelOutstandingConnections(for: peer, relayConnection: self.attempt(for: peer).relayConnection)
                return true
            } catch {
                self.application.logger.debug("DCUtR: direct dial failed for \(address): \(error)")
            }
        }

        return false
    }

    private func onConnected(_ connection: Connection) {
        guard self.isRelayConnection(connection), let peer = connection.remotePeer else { return }
        self.registerRelayConnection(connection, for: peer)
        self.refreshPeerInfo(for: peer)
        self.startPunchIfReady(for: peer)
    }

    private func onIdentifiedPeer(_ identifiedPeer: IdentifiedPeer) {
        self.refreshPeerInfo(for: identifiedPeer.peer)
        self.startPunchIfReady(for: identifiedPeer.peer)
    }

    private func onDisconnected(_ connection: Connection, _ peer: PeerID?) {
        guard let peer else { return }
        self.clearAttempt(for: peer)
        if self.isRelayConnection(connection) {
            self.application.logger.notice("DCUtR: relay connection closed for \(peer.b58String)")
        }
    }

    private func handle(_ req: Request) async throws -> Response<ByteBuffer> {
        guard let peer = req.remotePeer else { return .close }
        switch req.event {
        case .ready:
            var attempt = self.attempt(for: peer)
            if req.streamDirection == .outbound, attempt.connectSentAt == nil {
                // Spec step 2: the dialing side opens the stream and sends CONNECT first.
                attempt.connectSentAt = Date()
                self.setAttempt(attempt, for: peer)
                return .respond(try self.makePayload(type: .connect))
            }
            return .stayOpen

        case .data(let payload):
            let message = try DCUtRWire.decode(payload)
            let remoteInfo = try self.parsePeerInfo(from: message, fallbackPeer: peer)
            switch message.type {
            case .connect:
                var attempt = self.attempt(for: peer)
                attempt.remotePeerInfo = self.mergePeerInfo(attempt.remotePeerInfo, with: remoteInfo)
                attempt.connectReceivedAt = Date()
                self.setAttempt(attempt, for: peer)

                if req.streamDirection == .inbound {
                    // Spec step 3: the inbound side answers CONNECT with CONNECT.
                    return .respondThenClose(try self.makePayload(type: .connect))
                }

                let halfRTT: TimeInterval
                if let sentAt = attempt.connectSentAt {
                    halfRTT = max(0, Date().timeIntervalSince(sentAt) / 2.0)
                } else {
                    halfRTT = 0.05
                }

                let syncPayload = try self.makePayload(type: .sync)
                // Spec step 4: wait for half the relay RTT, then send SYNC to trigger simultaneous open.
                guard halfRTT > 0 else { return .respondThenClose(syncPayload) }
                try? await Task.sleep(nanoseconds: UInt64(halfRTT * 1_000_000_000))
                return .respondThenClose(syncPayload)

            case .sync:
                // Spec step 5/6: SYNC authorizes the direct dial and migration off the relay.
                if !self.dialDirect(for: peer, remoteInfo: remoteInfo) {
                    self.scheduleRetry(for: peer)
                }
                return .close
            }

        case .closed:
            return .close

        case .error(let error):
            req.logger.error("DCUtR: stream error: \(error)")
            return .close
        }
    }
}

extension HolePunch {
    init(type: HolePunch.Kind, obsAddrs: [Data]) {
        self.init()
        self.type = type
        self.obsAddrs = obsAddrs
    }
}
