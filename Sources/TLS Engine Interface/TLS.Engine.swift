public import Sockets
public import TLS

extension TLS {
    /// TLS engine integration namespace; concrete engines are leaf products.
    public enum Engine {}
}

extension TLS.Engine {
    /// An injected engine adapter that consumes a socket byte connection and yields an authenticated session.
    public struct Witness: Sendable {
        public let handshake: @Sendable (consuming Sockets.TCP.Connection, TLS.Configuration) async throws(TLS.Failure) -> (TLS.Session, TLS.Peer)

        public init(handshake: @escaping @Sendable (consuming Sockets.TCP.Connection, TLS.Configuration) async throws(TLS.Failure) -> (TLS.Session, TLS.Peer)) {
            self.handshake = handshake
        }

        /// Handshakes, then authenticates the certificate peer for the configured DNS hostname.
        public func wrap(socket: consuming Sockets.TCP.Connection, configuration: TLS.Configuration) async throws(TLS.Failure) -> TLS.Session {
            let (session, peer) = try await handshake(consume socket, configuration)
            try await configuration.peer.authenticate(peer, configuration.hostname)
            return session
        }
    }
}
