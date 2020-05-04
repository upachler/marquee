
use std::error::Error;
use rocket::State;
use rocket::request::{FromRequest,Outcome,Request};
use url::Url;

use openidconnect::*;
use openidconnect::core::*;
use openidconnect::reqwest::http_client;

type MetadataType = ProviderMetadata<EmptyAdditionalProviderMetadata, CoreAuthDisplay, CoreClientAuthMethod, CoreClaimName, CoreClaimType, CoreGrantType, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType>;

#[derive(Default)]
pub struct AuthManager {
    state: std::sync::Mutex<AuthState>
}

#[derive(Default)]
pub struct AuthState {
    metadata: Option<MetadataType>,
}

impl AuthManager {
    pub fn mk_login_url(&self) -> Result<Url,Box<dyn Error>> {
        self.state.lock().unwrap().mk_login_url()
    }
}

type AuthClient = Client<EmptyAdditionalClaims, CoreAuthDisplay, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreAuthPrompt, StandardErrorResponse<CoreErrorResponseType>, StandardTokenResponse<IdTokenFields<EmptyAdditionalClaims, EmptyExtraTokenFields, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType>, CoreTokenType>, CoreTokenType>;
impl AuthState {    

    fn discover_metadata(&mut self) -> Result<&Self,Box<dyn Error>>{

        let discovery_result = CoreProviderMetadata::discover(
            &IssuerUrl::new("http://localhost:8080/auth/realms/acme".to_string())?,
            http_client,
        );

        if let Err(de) = discovery_result {
            let errbox = match de {
                DiscoveryError::Parse(e) => Box::from(e),
                DiscoveryError::Other(msg) => Box::from(msg),
                DiscoveryError::Request(e) => Box::from("request error"),
                _ => Box::from("unknown error")
            };
            return Result::Err(errbox);
        }

        self.metadata = Option::Some(discovery_result.unwrap());
        
        Result::Ok(self)
    }

    fn client(&mut self) -> Result<AuthClient,Box<dyn Error>> {
        if let None = self.metadata {
            self.discover_metadata()?;
        }

        let client =
            CoreClient::from_provider_metadata(
                self.metadata.as_ref().unwrap(),
                ClientId::new("marquee".to_string()),
    //            Some(ClientSecret::new("client_secret".to_string())),
                None
            )
            // Set the URL the user will be redirected to after the authorization process.
            .set_redirect_uri(RedirectUrl::new("http://localhost:8000/token-exchange".to_string())?);
        
        Result::Ok(client)
    }

    pub fn mk_login_url(&mut self) -> Result<Url,Box<dyn Error>> {

        let client = self.client()?;
        
        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        
        // Generate the full authorization URL.
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new("read".to_string()))
            .add_scope(Scope::new("write".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();
        
        Result::Ok(auth_url)
    }
}
pub struct UserContext {

}

impl<'a,'r> FromRequest<'a, 'r> for UserContext {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> { 
        Outcome::Failure((rocket::http::Status::Unauthorized,()))
    }
}