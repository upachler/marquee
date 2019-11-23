


extern crate jsonwebtoken as jwt;

use std::sync::*;
use std::borrow::Cow;
use std::ops::Deref;

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

use discovery::OpenIDProviderConfiguration;

pub struct OIDCIssuerProvider {
    issuer_url: String,
    issuer_config: RwLock<Option<OpenIDProviderConfiguration>>,
}

impl OIDCIssuerProvider {
    pub fn new(issuer_url: &str) -> OIDCIssuerProvider {
        OIDCIssuerProvider {
            issuer_url: String::from(issuer_url),
            issuer_config: RwLock::default()
        }
    }

    fn acquire_config(&self) -> RwLockReadGuard<Option<OpenIDProviderConfiguration>> {
        let r = self.issuer_config.read().unwrap();
        
        match *r {
            None => {
                drop(r);
                *self.issuer_config.write().unwrap() = match discovery::fetch_configuration(&self.issuer_url) {
                    Ok(cfg) => Some(cfg),
                    Err(_) => None,
                };

            self.issuer_config.read().unwrap()
            },
            Some(_) => r
        }
    }

    fn fetch_from_config<F,R>(&self, fetch_fn: F) -> R 
    where F: Fn(&OpenIDProviderConfiguration) -> R,
    R: Default
    {
        let locked_config = self.acquire_config();
        match locked_config.deref().as_ref() {
            Some(cfg) => fetch_fn(cfg),
            None => R::default()
        }
    }
}

impl rocket_oauth2::Provider for OIDCIssuerProvider{

    fn token_uri(&self) -> Cow<'_, str> {
        Cow::Owned(self.fetch_from_config(|cfg| cfg.token_endpoint.clone()))
    }
    fn auth_uri(&self) -> Cow<'_, str> {
        Cow::Owned(self.fetch_from_config(|cfg| cfg.authorization_endpoint.clone()))
    }
}

mod discovery {
    use crate::serde::Deserialize;
    /// OpenID provider configuration, as obtained via the issuer endpoint.
    /// see (OpenID Discovery Spec)[https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery#rfc.section.3 "Section 3"]
    #[derive(Deserialize, Default, Clone)]
    #[allow(unused)]
    pub struct OpenIDProviderConfiguration {
        issuer: String,
        pub authorization_endpoint: String, 
        pub token_endpoint: String,
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

    
    pub fn fetch_configuration(openid_configuration_uri : &str) -> reqwest::Result<OpenIDProviderConfiguration>{
        let client = reqwest::Client::new();
        let mut url = reqwest::Url::parse(openid_configuration_uri).expect("invalid OpenID issuer URL");
        if(!url.path().ends_with("/")) {
            url.set_path(&(String::from(url.path()) + "/"))
        }
        let url = url.join(".well-known/openid-configuration").unwrap();
        let mut res = client.get(url).send()?;
        res.json::<OpenIDProviderConfiguration>()
    }
}
