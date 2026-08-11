public import Byte_Channel
public import TLS

extension TLS {
    /// TLS engine integration namespace; concrete engines are leaf products.
    public enum Engine {}
}

extension TLS.Engine {
    /// An injected engine adapter that transforms an encrypted byte channel into an authenticated session.
    public struct Witness: Sendable {
        /// The engine receives encrypted bytes and returns their authenticated plaintext session.
        ///
        /// The implementation preserves handshake, record, truncation, and close outcomes through
        /// `TLS.Failure`; it does not select an endpoint, scheduler, or cryptographic implementation.
        public let handshake: @Sendable (consuming Byte.Channel<TLS.Failure>, TLS.Configuration) async throws(TLS.Failure) -> (TLS.Session, TLS.Peer)

        public init(handshake: @escaping @Sendable (consuming Byte.Channel<TLS.Failure>, TLS.Configuration) async throws(TLS.Failure) -> (TLS.Session, TLS.Peer)) {
            self.handshake = handshake
        }

        /// Handshakes the encrypted channel, then authenticates its certificate peer for the configured DNS hostname.
        public func wrap(encrypted: consuming Byte.Channel<TLS.Failure>, configuration: TLS.Configuration) async throws(TLS.Failure) -> TLS.Session {
            let (session, peer) = try await handshake(consume encrypted, configuration)
            try await configuration.peer.authenticate(peer, configuration.hostname)
            return session
        }
    }
}
