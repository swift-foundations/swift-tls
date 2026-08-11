# swift-tls

`TLS` is the engine-neutral TLS session and peer-policy surface for the Swift Foundations ecosystem.

`TLS.Peer.Identity` is the sole relation binding a `DNS.Query` to the hostname used for both Server Name Indication and certificate authentication. `TLS.Configuration` carries that identity and `TLS.PeerPolicy`; resolution projects `identity.query`, authentication projects `identity.hostname`, and no independently variable query/hostname pair exists on the configuration.

TLS reuses the provider-neutral `Domain Name System` product at `930ab8b5dadc99d6c44b101d92422545b697db7d` for `DNS.Query`, `DNS.Response`, `DNS.Resolver`, and `DNS.Resolving`. It does not depend on or import the separate `Domain Name System Cache` product. Because SwiftPM resolves a package's complete dependency declaration, the DNS package's Cache Primitives dependency remains in package-wide resolution even though it is absent from the TLS target's product and import closure.

Consumers that need `TLS.Engine.Witness` without selecting a platform engine import the `TLS Engine Interface` library product. The witness consumes `Byte.Channel<TLS.Failure>` encrypted transport and yields an authenticated plaintext session. It preserves handshake, peer-policy, record, truncation, close, and typed-failure behavior without selecting a socket or provider.

The interface reuses the frozen Byte Channel producer at `dfc56d1ed173aae4db784018c746050cbfbe4ee7`, including its owned `Byte.Chunk` and typed `Index<Byte>.Count` surface. A session is non-Sendable and uniquely moved with `consuming sending` into its owning actor region; its read, write, close, and drop operations transfer into that session as `sending` escaping closures rather than independently reusable `@Sendable` values. A session read returns `nil` only for authenticated `close_notify`; premature physical or channel EOF is `.truncated`. A zero maximum returns an owned empty chunk without transport I/O, while a positive maximum cannot return an empty progressless chunk. Writes borrow the caller's chunk, retaining caller ownership on success and failure. The engine witness and peer policy remain `@Sendable` because those immutable factories are genuinely shared across independently concurrent connections.

The `TLS Apple Engine`, `TLS OpenSSL Engine`, and `TLS SChannel Engine` products are leaves. Each exposes an injected `TLS.Engine.Witness` that consumes the transport-neutral byte channel, authenticates the configured peer, and produces the session. They deliberately do not add cryptography, provider policy, pooling, Foundation, or platform imports to the core target. Socket binding remains a downstream composition concern.

An engine maps encrypted-channel termination into `TLS.Failure`: a declared failure is preserved exactly and cancellation remains cancellation. EOF, `.finished`, and `.closed` become `.closed` only after an authenticated TLS `close_notify`; otherwise they become `.truncated`. Awaited `.full` and `.empty` are unreachable and are defensively represented as `.transport`.

## Current engine blockers

Apple needs an owned Security.framework binding target; OpenSSL needs an owned module target and link contract; SChannel needs an owned WinSDK binding target. Until those targets exist, each leaf exposes the exact injected backend witness rather than fabricating a cryptographic implementation.

## Verification status

This initial branch is intentionally **UNVERIFIED**. TX-N4 prohibits build, resolve, test, CI dispatch, and compiler-driven repair in this change.
