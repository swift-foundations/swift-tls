public import Byte_Channel
public import TLS

// Static negative control: the engine-neutral interface remains transport-neutral.
#if canImport(Sockets)
    #error("TLS Engine Interface must not depend on Sockets")
#endif

extension TLS {
    /// TLS engine integration namespace; concrete engines are leaf products.
    public enum Engine {}
}

extension TLS.Failure {
    /// Maps an encrypted byte-channel terminal outcome into the TLS session failure domain.
    ///
    /// `nil` represents EOF from `Byte.Channel.Reader.receive()`. EOF, `.finished`, and
    /// `.closed` are a clean TLS close only after the engine authenticated `close_notify`;
    /// otherwise they are truncation. A declared channel failure is preserved exactly, and
    /// cancellation remains cancellation. Awaited channel operations cannot produce `.full`
    /// or `.empty`; these cases remain defensively typed as `.transport`.
    public static func terminal(
        _ channel: Byte.Channel<TLS.Failure>.Error?,
        authenticatedCloseNotify: Bool
    ) -> TLS.Failure {
        switch channel {
        case .some(.failed(let failure)):
            return failure
        case .some(.cancelled):
            return .cancelled
        case .none, .some(.finished), .some(.closed):
            return authenticatedCloseNotify ? .closed : .truncated
        case .some(.full), .some(.empty):
            return .transport
        }
    }
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
            do throws(TLS.Failure) {
                try await configuration.peer.authenticate(peer, configuration.identity.hostname)
                return session
            } catch let failure as TLS.Failure {
                await session.close()
                throw failure
            }
        }
    }
}
