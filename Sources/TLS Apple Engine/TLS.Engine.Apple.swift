public import TLS
public import TLS_Engine_Interface

extension TLS.Engine {
    /// Apple Security.framework adapter contract. Concrete bindings remain pending the
    /// owned platform surface.
    public enum Apple: Sendable {
        public static func witness(_ backend: TLS.Engine.Witness) -> TLS.Engine.Witness { backend }
    }
}
