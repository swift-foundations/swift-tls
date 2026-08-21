extension TLS {

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

        public func read(maximum: Int) async throws(TLS.Failure) -> [UInt8] {
            guard !Task.isCancelled else { throw .cancelled }
            return try await readOperation(maximum)
        }

        public func write(_ bytes: [UInt8]) async throws(TLS.Failure) {
            guard !Task.isCancelled else { throw .cancelled }
            try await writeOperation(bytes)
        }

        public func close() async {
            await closeOperation()
        }
    }
}
