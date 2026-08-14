public import TLS_Engine_Interface

// Static negative control: platform TLS leaves do not own socket composition.
#if canImport(Sockets)
    #error("TLS SChannel Engine must not depend on Sockets")
#endif

extension TLS.Engine {
    /// Windows SChannel adapter contract. Concrete bindings remain pending the owned WinSDK binding target.
    public enum SChannel: Sendable {
        public static func witness(_ backend: TLS.Engine.Witness) -> TLS.Engine.Witness { backend }
    }
}
