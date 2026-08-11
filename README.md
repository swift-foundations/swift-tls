# swift-tls

`TLS` is the engine-neutral TLS session and peer-policy surface for the Swift Foundations ecosystem.

`TLS.Configuration` carries the selected DNS query, DNS hostname, and `TLS.PeerPolicy`. An engine must use that hostname for both handshake identity and peer authentication, then return a `TLS.Session` with async read, write, and close.

Consumers that need `TLS.Engine.Witness` without selecting a platform engine import the `TLS Engine Interface` library product. The witness consumes `Byte.Channel<TLS.Failure>` encrypted transport and yields an authenticated plaintext session. It preserves handshake, peer-policy, record, truncation, close, and typed-failure behavior without selecting a socket or provider.

The `TLS Apple Engine`, `TLS OpenSSL Engine`, and `TLS SChannel Engine` products are leaves. Each exposes an injected `TLS.Engine.Witness` that consumes the transport-neutral byte channel, authenticates the configured peer, and produces the session. They deliberately do not add cryptography, provider policy, pooling, Foundation, or platform imports to the core target. Socket binding remains a downstream composition concern.

An engine maps encrypted-channel termination into `TLS.Failure`: a declared failure is preserved exactly and cancellation remains cancellation. EOF, `.finished`, and `.closed` become `.closed` only after an authenticated TLS `close_notify`; otherwise they become `.truncated`. Awaited `.full` and `.empty` are unreachable and are defensively represented as `.transport`.

## Current engine blockers

Apple needs an owned Security.framework binding target; OpenSSL needs an owned module target and link contract; SChannel needs an owned WinSDK binding target. Until those targets exist, each leaf exposes the exact injected backend witness rather than fabricating a cryptographic implementation.

## Verification status

This initial branch is intentionally **UNVERIFIED**. TX-N4 prohibits build, resolve, test, CI dispatch, and compiler-driven repair in this change.
