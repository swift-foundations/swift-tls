import TLS
import TLS_Apple_Engine
import TLS_OpenSSL_Engine
import TLS_SChannel_Engine

// Static contract source: runtime verification is explicitly deferred by TX-N4's moratorium.
// The imports prove each public product independently exposes the shared TLS.Engine witness.
let apple = TLS.Engine.Apple.self
let openSSL = TLS.Engine.OpenSSL.self
let schannel = TLS.Engine.SChannel.self
let session = TLS.Session.self
let configuration = TLS.Configuration.self
let policy = TLS.PeerPolicy.self
