public import DNS

extension TLS.Peer {
    /// The single relation binding endpoint selection to TLS server identity.
    ///
    /// The DNS question selects the peer, while the hostname is the exact value used for
    /// Server Name Indication and certificate authentication. Keeping the pair in this value
    /// prevents those two identity projections from diverging in a configuration.
    public struct Identity: Sendable {
        public let query: DNS.Query
        public let hostname: String

        public init(query: DNS.Query, hostname: String) {
            self.query = query
            self.hostname = hostname
        }
    }
}
