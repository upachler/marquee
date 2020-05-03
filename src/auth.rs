
use std::error::Error;
use rocket::request::{FromRequest,Outcome,Request};
use url::Url;

use openidconnect::*;
use openidconnect::core::*;
use openidconnect::reqwest::http_client;


pub fn mk_redirect_url() -> Result<Url,Box<dyn Error>> {
    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.

    let discovery_result = CoreProviderMetadata::discover(
        &IssuerUrl::new("http://localhost:8080/auth/realms/acme".to_string())?,
        http_client,
    );
    let metadata = match discovery_result {
        Ok(md) => md,
        Err(_) => return Result::Err(Box::from("discovery error"))
    };
    let client =
        CoreClient::from_provider_metadata(
            metadata,
            ClientId::new("marquee".to_string()),
//            Some(ClientSecret::new("client_secret".to_string())),
            None
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new("http://localhost:8000/token-exchange".to_string())?);
    
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

pub struct UserContext {

}

impl<'a,'r> FromRequest<'a, 'r> for UserContext {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> { 
        Outcome::Failure((rocket::http::Status::Unauthorized,()))
    }
}