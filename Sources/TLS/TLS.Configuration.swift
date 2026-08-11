public import DNS
public import IP_Address

extension TLS {
    /// The connection identity and peer rules an engine must authenticate.
    public struct Configuration: Sendable {
        /// The inseparable DNS-selection and TLS-authentication identity.
        public let identity: TLS.Peer.Identity
        /// The certificate policy applied to the authenticated peer.
        public let peer: TLS.PeerPolicy

        public init(identity: TLS.Peer.Identity, peer: TLS.PeerPolicy) {
            self.identity = identity
            self.peer = peer
        }

        /// Resolves the configured DNS question through the caller's cancellable resolver.
        public func resolve<Resolver: DNS.Resolving>(using resolver: Resolver) async throws(Resolver.Failure) -> [IP.Address] {
            try await resolver.resolve(identity.query)
        }
    }
}
