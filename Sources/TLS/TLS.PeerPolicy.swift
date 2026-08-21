public import Certificates

extension TLS {

    public struct Peer: Sendable {

        public let chain: ValidatedCertificateChain

        public init(chain: ValidatedCertificateChain) {
            self.chain = chain
        }
    }

    public struct PeerPolicy: Sendable {

        public let authenticate: @Sendable (TLS.Peer, String) async throws(TLS.Failure) -> Void

        public init(
            authenticate: @escaping @Sendable (TLS.Peer, String) async throws(TLS.Failure) -> Void
        ) {
            self.authenticate = authenticate
        }
    }

    public enum Failure: Swift.Error, Sendable {
        case cancelled
        case handshake
        case peer
        case closed
        case transport
    }
}
