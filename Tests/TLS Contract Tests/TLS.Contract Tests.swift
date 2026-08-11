import TLS
import TLS_Apple_Engine
import TLS_Engine_Interface
import TLS_OpenSSL_Engine
import TLS_SChannel_Engine

// Static contract source: runtime verification is explicitly deferred by TX-N4's moratorium.
// The interface binds transport injection to the typed byte channel; peer policy, close, and
// terminal failure remain public session laws rather than socket or provider behavior.
let apple = TLS.Engine.Apple.self
let openSSL = TLS.Engine.OpenSSL.self
let schannel = TLS.Engine.SChannel.self
let witness = TLS.Engine.Witness.self
let encryptedChannel = Byte.Channel<TLS.Failure>.self
let peerAuthentication = TLS.PeerPolicy.authenticate
let session = TLS.Session.self
let sessionClose = TLS.Session.close
let configuration = TLS.Configuration.self
let policy = TLS.PeerPolicy.self
let transportFailure: TLS.Failure = .transport
let closedFailure: TLS.Failure = .closed
let truncatedFailure: TLS.Failure = .truncated
let failedTerminal = TLS.Failure.terminal(.failed(.handshake), authenticatedCloseNotify: false)
let cancelledTerminal = TLS.Failure.terminal(.cancelled, authenticatedCloseNotify: false)
let eofAfterCloseNotify = TLS.Failure.terminal(nil, authenticatedCloseNotify: true)
let eofWithoutCloseNotify = TLS.Failure.terminal(nil, authenticatedCloseNotify: false)
let finishedAfterCloseNotify = TLS.Failure.terminal(.finished, authenticatedCloseNotify: true)
let closedWithoutCloseNotify = TLS.Failure.terminal(.closed, authenticatedCloseNotify: false)
let defensiveFullTerminal = TLS.Failure.terminal(.full, authenticatedCloseNotify: false)
let defensiveEmptyTerminal = TLS.Failure.terminal(.empty, authenticatedCloseNotify: false)

// Ownership source laws: Session is storable and returnable, but operations borrow its unique
// value and close consumes it. Its required synchronous drop hook is distinct from async close.
struct SessionOwner: ~Copyable {
    var session: TLS.Session
}

func read(session: borrowing TLS.Session, maximum: Int) async throws(TLS.Failure) -> [UInt8] {
    try await session.read(maximum: maximum)
}

func write(session: borrowing TLS.Session, bytes: [UInt8]) async throws(TLS.Failure) {
    try await session.write(bytes)
}

func close(session: consuming TLS.Session) async {
    await session.close()
}

func session(
    close: @escaping @Sendable () async -> Void,
    drop: @escaping @Sendable () -> Void
) -> TLS.Session {
    TLS.Session(
        read: { _ in [] },
        write: { _ in },
        close: close,
        drop: drop
    )
}

// Authentication source law: Witness.wrap owns the post-handshake Session. Its typed failure
// branch awaits consuming close before rethrowing the unchanged TLS.Failure.
