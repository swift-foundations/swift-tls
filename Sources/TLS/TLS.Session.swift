extension TLS {
    /// An authenticated plaintext byte session supplied by an injected TLS engine.
    // SAFETY: The injected operations own their synchronization and remain valid only until close.
    public final class Session: @unchecked Sendable {
        private let readOperation: @Sendable (Int) async throws(TLS.Failure) -> [UInt8]
        private let writeOperation: @Sendable ([UInt8]) async throws(TLS.Failure) -> Void
        private let closeOperation: @Sendable () async -> Void

        public init(
            read: @escaping @Sendable (Int) async throws(TLS.Failure) -> [UInt8],
            write: @escaping @Sendable ([UInt8]) async throws(TLS.Failure) -> Void,
            close: @escaping @Sendable () async -> Void
        ) {
            self.readOperation = read
            self.writeOperation = write
            self.closeOperation = close
        }

        /// Reads decrypted bytes, returning an empty array at end of stream.
        public func read(maximum: Int) async throws(TLS.Failure) -> [UInt8] {
            guard !Task.isCancelled else { throw .cancelled }
            return try await readOperation(maximum)
        }

        /// Writes plaintext bytes through the authenticated TLS record layer.
        public func write(_ bytes: [UInt8]) async throws(TLS.Failure) {
            guard !Task.isCancelled else { throw .cancelled }
            try await writeOperation(bytes)
        }

        /// Closes this TLS and byte-channel session.
        ///
        /// A downstream composer owns closing any physical transport.
        public func close() async {
            await closeOperation()
        }
    }
}
