public import TLS
public import TLS_Engine_Interface

extension TLS.Engine {

    public enum OpenSSL: Sendable {
        public static func witness(_ backend: TLS.Engine.Witness) -> TLS.Engine.Witness { backend }
    }
}
