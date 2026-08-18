public import Domain_Name_System
public import IP_Address

extension TLS {
    /// The connection identity and peer rules an engine must authenticate.
    public struct Configuration: Sendable {
        /// The DNS question that selected the connection peer.
        public let query: DNS.Query
        /// The DNS hostname used for SNI and certificate authentication.
        public let hostname: String
        /// The certificate policy applied to the authenticated peer.
        public let peer: TLS.PeerPolicy

        public init(query: DNS.Query, hostname: String, peer: TLS.PeerPolicy) {
            self.query = query
            self.hostname = hostname
            self.peer = peer
        }

        /// Resolves the configured DNS question through the caller's cancellable resolver.
        public func resolve<Resolver: DNS.Resolving>(
            using resolver: Resolver
        ) async throws(Resolver.Failure) -> [IP.Address] {
            try await resolver.resolve(query)
        }
    }
}
