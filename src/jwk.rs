

mod jwk {
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[allow(unused)]
    pub struct JWK {
        /// "kty" (Key Type) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.1
        kty: String,
        /// "use" (Public Key Use) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.2
        #[serde(rename="use")]
        use_: String,
        /// key_ops" (Key Operations) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.3
        key_ops: Vec<String>,
        /// "alg" (Algorithm) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.4
        alg: String,
        /// "kid" (Key ID) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.5
        kid: String,
        /// "x5u" (X.509 URL) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.6
        x5u: String,
        /// "x5c" (X.509 Certificate Chain) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.7
        x5c: String,
        /// "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.8
        x5t: String,
        /// "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter
        /// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.9
        #[serde(rename="x5t#S256")]
        x5t_S256: String
    }

    #[derive(Deserialize)]
    pub struct JWKSet {
        keys: Vec<JWK>
    }
}