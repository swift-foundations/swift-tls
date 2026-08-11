public import TLS_Engine_Interface

extension TLS.Engine {
    /// OpenSSL adapter contract. Concrete bindings remain pending an owned OpenSSL module target.
    public enum OpenSSL: Sendable {
        public static func witness(_ backend: TLS.Engine.Witness) -> TLS.Engine.Witness { backend }
    }
}
