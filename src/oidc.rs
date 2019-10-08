


extern crate jsonwebtoken as jwt;

mod oidc {
    enum Error {
        JWTError(jwt::errors::Error),
    }
    impl From<jwt::errors::Error> for Error  {
        fn from(error: jwt::errors::Error) -> Error {
            Error::JWTError(error)
        }
    }

    struct OpenidContext {
        /// https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.4
        openid_configuration_url: String,
        /// URI to acquire the JWKSet from the OP if Some;
        /// None if config was not loaded yet
        jwks_uri: Option<String>,
        /// public key used for verification if Some, otherwise
        /// None if no key is present yet
        key: Option<Vec<u8>>,
        validation: Option<jwt::Validation>,
    }
    
    use serde::Deserialize;

    impl OpenidContext {

        // 
        pub fn validate_jwt<T>(self: &mut OpenidContext, token: &str) -> Result<jwt::TokenData<T>,Error>
            where for<'de> T: Deserialize<'de>
        {
            
            self.prepare()?;

            match jwt::decode::<T>(token, self.key.as_ref().unwrap().as_slice(), self.validation.as_ref().unwrap()) {
                Ok(t) => Ok(t),
                Err(e) => Err(Error::from(e))
            }
        }

        fn prepare(self: &mut OpenidContext) -> Result<(),Error>{
            Result::Ok(())
        }
        fn acquire_config() -> Result<(),Error>{
            Result::Ok(())
        }
    }

    
    mod discovery {
        use crate::serde::Deserialize;
         /// OpenID provider configuration, as obtained via the issuer endpoint.
        /// see (OpenID Discovery Spec)[https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery#rfc.section.3 "Section 3"]
        #[derive(Deserialize, Default)]
        pub struct OpenIDProviderConfiguration {
            issuer: String,
            authorization_endpoint: String, 
            token_endpoint: String,
            token_introspection_endpoint: String,
            userinfo_endpoint: String,
            end_session_endpoint: String,
            jwks_uri: String,check_session_iframe: String,
            grant_types_supported: Vec<String>,
            response_types_supported: Vec<String>,
            subject_types_supported: Vec<String>,
            id_token_signing_alg_values_supported: Vec<String>,
            userinfo_signing_alg_values_supported: Vec<String>,
            request_object_signing_alg_values_supported: Vec<String>,
            response_modes_supported: Vec<String>,
            registration_endpoint: String,
            token_endpoint_auth_methods_supported: Vec<String>,
            token_endpoint_auth_signing_alg_values_supported: Vec<String>,
            claims_supported: Vec<String>,
            claim_types_supported: Vec<String>,
            claims_parameter_supported: bool,
            scopes_supported: Vec<String>,
            request_parameter_supported: bool, 
            request_uri_parameter_supported: bool,
            code_challenge_methods_supported: Vec<String>,
            tls_client_certificate_bound_access_tokens: bool,
            introspection_endpoint: String,
        }

        fn fetch_configuration(openid_configuration_uri : &str) -> reqwest::Result<OpenIDProviderConfiguration>{
            let client = reqwest::Client::new();
            
            let mut res = client.get(openid_configuration_uri).send()?;
            let mut config = OpenIDProviderConfiguration::default();
            res.json::<OpenIDProviderConfiguration>()
        }
    }
}