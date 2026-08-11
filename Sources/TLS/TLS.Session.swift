extension TLS {
    /// An authenticated plaintext byte session supplied by an injected TLS engine.
    ///
    /// The session has unique ownership. Borrow it to read or write, and consume it to perform
    /// the asynchronous TLS close exactly once. Dropping an unclosed session synchronously
    /// cancels its engine state; asynchronous protocol cleanup requires an explicit `close()`.
    public struct Session: ~Copyable, Sendable {
        private let readOperation: @Sendable (Int) async throws(TLS.Failure) -> [UInt8]
        private let writeOperation: @Sendable ([UInt8]) async throws(TLS.Failure) -> Void
        private var closeOperation: (@Sendable () async -> Void)?
        private let dropOperation: @Sendable () -> Void

        public init(
            read: @escaping @Sendable (Int) async throws(TLS.Failure) -> [UInt8],
            write: @escaping @Sendable ([UInt8]) async throws(TLS.Failure) -> Void,
            close: @escaping @Sendable () async -> Void,
            drop: @escaping @Sendable () -> Void
        ) {
            self.readOperation = read
            self.writeOperation = write
            self.closeOperation = close
            self.dropOperation = drop
        }

        deinit {
            guard case .some = closeOperation else { return }
            dropOperation()
        }
    }
}

extension TLS.Session {
    /// Reads decrypted bytes, returning an empty array at end of stream.
    public borrowing func read(maximum: Int) async throws(TLS.Failure) -> [UInt8] {
        guard !Task.isCancelled else { throw .cancelled }
        return try await readOperation(maximum)
    }

    /// Writes plaintext bytes through the authenticated TLS record layer.
    public borrowing func write(_ bytes: [UInt8]) async throws(TLS.Failure) {
        guard !Task.isCancelled else { throw .cancelled }
        try await writeOperation(bytes)
    }

    /// Closes this TLS and byte-channel session.
    ///
    /// This consumes the session and performs its nonthrowing asynchronous close exactly
    /// once. A downstream composer owns closing any physical transport.
    public consuming func close() async {
        let close = closeOperation
        closeOperation = nil
        await close?()
    }
}
