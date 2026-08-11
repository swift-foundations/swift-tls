public import TLS_Engine_Interface

// Static negative control: platform TLS leaves do not own socket composition.
#if canImport(Sockets)
    #error("TLS OpenSSL Engine must not depend on Sockets")
#endif

extension TLS.Engine {
    /// OpenSSL adapter contract. Concrete bindings remain pending an owned OpenSSL module target.
    public enum OpenSSL: Sendable {
        public static func witness(_ backend: TLS.Engine.Witness) -> TLS.Engine.Witness { backend }
    }
}
