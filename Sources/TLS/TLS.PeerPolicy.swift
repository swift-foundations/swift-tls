public import Certificates

extension TLS {
    /// A verified peer identity supplied by a TLS engine after handshake.
    public struct Peer: Sendable {
        /// The validated chain, ordered from leaf to trust anchor.
        public let chain: ValidatedCertificateChain

        public init(chain: ValidatedCertificateChain) {
            self.chain = chain
        }
    }

    /// The policy boundary between an engine's handshake and a consumer session.
    public struct PeerPolicy: Sendable {
        /// Rejects a peer that is not authenticated for the configuration hostname.
        public let authenticate: @Sendable (TLS.Peer, String) async throws(TLS.Failure) -> Void

        public init(authenticate: @escaping @Sendable (TLS.Peer, String) async throws(TLS.Failure) -> Void) {
            self.authenticate = authenticate
        }
    }

    /// Session lifecycle failure, including cancellation and peer rejection.
    public enum Failure: Swift.Error, Sendable {
        case cancelled
        case handshake
        case peer
        case closed
        case transport
    }
}
