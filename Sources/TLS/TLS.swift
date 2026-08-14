// Static negative control: the TLS core remains independent of socket ownership.
#if canImport(Sockets)
    #error("TLS core must not depend on Sockets")
#endif

/// Engine-neutral transport-layer security vocabulary.
public enum TLS {}
