public import Byte_Chunk
public import Byte_Primitives
public import Index_Primitives

extension TLS {
    /// An authenticated plaintext byte session supplied by an injected TLS engine.
    ///
    /// The session has unique ownership. Borrow it to read or write, and consume it to perform
    /// the asynchronous TLS close exactly once. Dropping an unclosed session synchronously
    /// cancels its engine state; asynchronous protocol cleanup requires an explicit `close()`.
    public struct Session: ~Copyable, Sendable {
        private let readOperation: @Sendable (Index<Byte>.Count) async throws(TLS.Failure) -> sending Byte.Chunk?
        private let writeOperation: @Sendable (borrowing Byte.Chunk) async throws(TLS.Failure) -> Void
        private var closeOperation: (@Sendable () async -> Void)?
        private let dropOperation: @Sendable () -> Void

        public init(
            read: @escaping @Sendable (Index<Byte>.Count) async throws(TLS.Failure) -> sending Byte.Chunk?,
            write: @escaping @Sendable (borrowing Byte.Chunk) async throws(TLS.Failure) -> Void,
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
    /// Reads decrypted bytes, returning `nil` only after authenticated `close_notify`.
    ///
    /// A zero maximum returns an owned empty chunk without invoking the engine. A positive
    /// maximum never reports an empty progressless chunk; an engine doing so is a transport
    /// contract failure. Physical or encrypted-channel EOF before `close_notify` is `.truncated`.
    public borrowing func read(
        maximum: Index<Byte>.Count
    ) async throws(TLS.Failure) -> sending Byte.Chunk? {
        guard !Task.isCancelled else { throw .cancelled }
        guard maximum != .zero else {
            return Byte.Chunk.Input(capacity: .zero).finish()
        }

        guard let chunk = try await readOperation(maximum) else { return nil }
        guard chunk.count != .zero else { throw .transport }
        return consume chunk
    }

    /// Writes plaintext bytes through the authenticated TLS record layer.
    public borrowing func write(_ plaintext: borrowing Byte.Chunk) async throws(TLS.Failure) {
        guard !Task.isCancelled else { throw .cancelled }
        try await writeOperation(plaintext)
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
