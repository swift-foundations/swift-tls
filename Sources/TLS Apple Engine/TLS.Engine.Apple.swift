public import TLS_Engine_Interface

// Static negative control: platform TLS leaves do not own socket composition.
#if canImport(Sockets)
    #error("TLS Apple Engine must not depend on Sockets")
#endif

extension TLS.Engine {
    /// Apple Security.framework adapter contract. Concrete bindings remain pending the owned platform surface.
    public enum Apple: Sendable {
        public static func witness(_ backend: TLS.Engine.Witness) -> TLS.Engine.Witness { backend }
    }
}
