public import TLS
public import TLS_Engine_Interface

extension TLS.Engine {
    /// Windows SChannel adapter contract. Concrete bindings remain pending the owned
    /// WinSDK binding target.
    public enum SChannel: Sendable {
        public static func witness(_ backend: TLS.Engine.Witness) -> TLS.Engine.Witness { backend }
    }
}
