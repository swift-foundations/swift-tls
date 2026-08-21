public import Sockets
public import TLS

extension TLS {

    public enum Engine {}
}

extension TLS.Engine {

    public struct Witness: Sendable {
        public let handshake:
            @Sendable (
                consuming Sockets.TCP.Connection, TLS.Configuration
            ) async throws(TLS.Failure) -> (TLS.Session, TLS.Peer)

        public init(
            handshake:
                @escaping @Sendable (
                    consuming Sockets.TCP.Connection, TLS.Configuration
                ) async throws(TLS.Failure) -> (TLS.Session, TLS.Peer)
        ) {
            self.handshake = handshake
        }

        public func wrap(
            socket: consuming Sockets.TCP.Connection,
            configuration: TLS.Configuration
        ) async throws(TLS.Failure) -> TLS.Session {
            let (session, peer) = try await handshake(consume socket, configuration)
            try await configuration.peer.authenticate(peer, configuration.hostname)
            return session
        }
    }
}
