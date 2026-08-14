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
let identity = TLS.Peer.Identity.self
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

func read(
    session: borrowing TLS.Session,
    maximum: Index<Byte>.Count
) async throws(TLS.Failure) -> sending Byte.Chunk? {
    try await session.read(maximum: maximum)
}

func write(session: borrowing TLS.Session, plaintext: borrowing Byte.Chunk) async throws(TLS.Failure) {
    try await session.write(plaintext)
}

func close(session: consuming TLS.Session) async {
    await session.close()
}

func session(
    close: sending @escaping () async -> Void,
    drop: sending @escaping () -> Void
) -> TLS.Session {
    TLS.Session(
        read: { _ in Byte.Chunk.Input(capacity: .zero).finish() },
        write: { _ in },
        close: close,
        drop: drop
    )
}

// Region-transfer source law: Session is deliberately non-Sendable. Its unique value and
// non-Sendable stored operations cross into one actor only through consuming+sending transfer.
// The actor then borrows that owned session for operations and consumes it exactly once to close.
actor SessionRegion {
    func own(
        _ session: consuming sending TLS.Session,
        maximum: Index<Byte>.Count
    ) async throws(TLS.Failure) {
        if let plaintext = try await session.read(maximum: maximum) {
            let count = plaintext.count
            _ = count
        }
        await session.close()
    }
}

func transfer(
    _ session: consuming sending TLS.Session,
    to region: SessionRegion,
    maximum: Index<Byte>.Count
) async throws(TLS.Failure) {
    try await region.own(consume session, maximum: maximum)
}

// Identity non-divergence source law: Configuration accepts only the relation owner, never an
// independently variable query/hostname pair. Resolution projects identity.query and
// Witness authentication projects the same identity's hostname.
func configuration(identity: TLS.Peer.Identity, peer: TLS.PeerPolicy) -> TLS.Configuration {
    TLS.Configuration(identity: identity, peer: peer)
}

// Owned-read source law: the optional chunk is moved from the session boundary. Pattern
// matching observes nil without asking #expect to copy a move-only Optional; count is projected
// to its Copyable typed value before any assertion framework could observe it.
func readCount(
    session: borrowing TLS.Session,
    maximum: Index<Byte>.Count
) async throws(TLS.Failure) -> Index<Byte>.Count? {
    guard let plaintext = try await session.read(maximum: maximum) else { return nil }
    return plaintext.count
}

// Borrowed-write source law: accessing count after either path proves the caller retained the
// move-only chunk. The session operation cannot consume it on success or failure.
func writeRetainsOnSuccess(
    session: borrowing TLS.Session,
    plaintext: borrowing Byte.Chunk
) async throws(TLS.Failure) -> Index<Byte>.Count {
    try await session.write(plaintext)
    return plaintext.count
}

func writeRetainsOnFailure(
    session: borrowing TLS.Session,
    plaintext: borrowing Byte.Chunk
) async -> Index<Byte>.Count {
    do throws(TLS.Failure) {
        try await session.write(plaintext)
    } catch {
        return plaintext.count
    }
    return plaintext.count
}

// Read-law source matrix:
// - maximum == .zero: Session returns an owned empty chunk before invoking its transport hook.
// - maximum > .zero: an engine-produced empty chunk throws .transport rather than reporting
//   progressless success.
// - nil: reserved for authenticated close_notify; channel/physical EOF maps through terminal
//   to .truncated unless authenticatedCloseNotify is true.
// - cancellation: read and write reject a pre-cancelled task with .cancelled.
// Close/drop law: consuming close clears the guarded hook before awaiting it; dropping an
// unclosed session invokes only the synchronous drop hook. No span borrow appears in an async
// operation, so no lifetime-bound view can cross suspension.
// Stored-operation law: Session initializer parameters are sending escaping closures moved into
// one unique session region. They are not @Sendable because no independently concurrent owner
// may retain or reuse them. The move-only Session has no Sendable conformance and no aliasing shim.
// Authentication law: Witness.wrap owns the post-handshake Session. Its typed failure branch
// awaits consuming close before rethrowing the unchanged TLS.Failure.

// Sockets-negative source law: every production target carries a canImport(Sockets) failure
// sentinel, and Package.swift declares no Sockets package or product edge.
