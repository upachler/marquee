
use url::Url;
use rocket::State;
use rocket::request::{FromRequest,Outcome,Request};

use openidconnect::*;
use openidconnect::core::*;
use openidconnect::reqwest::http_client;
use failure::Fail;

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

    pub fn mk_login_url(&self, initial_target: &str) -> Result<(Url,String),Box<dyn std::error::Error>> {
        self.state.lock().unwrap().mk_login_url(initial_target)
    }

    pub fn validate(&self, bearer_token: &str) -> Result<(),Box<dyn std::error::Error>> {
        self.state.lock().unwrap().validate(bearer_token)
    }

    pub fn exchange_code(&self, code: &str, nonce: &str) -> Result<String,Box<dyn std::error::Error>> {
        self.state.lock().unwrap().exchange_code(code, nonce)
    }
}

type AuthClient = Client<EmptyAdditionalClaims, CoreAuthDisplay, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreAuthPrompt, StandardErrorResponse<CoreErrorResponseType>, StandardTokenResponse<IdTokenFields<EmptyAdditionalClaims, EmptyExtraTokenFields, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType>, CoreTokenType>, CoreTokenType>;
impl AuthState {    

    fn discover_metadata(&mut self) -> Result<&Self,Box<dyn std::error::Error>>{

        let discovery_result = CoreProviderMetadata::discover(
            &IssuerUrl::new("http://localhost:8080/auth/realms/acme".to_string())?,
            http_client,
        );

        if let Err(de) = discovery_result {
            use DiscoveryError::*;
            let errbox = match de {
                Parse(e) => Box::from(e),
                Other(msg) => Box::from(msg),
                Request(e) => Box::from("request error"),
                _ => Box::from("unknown error")
            };
            return Result::Err(errbox);
        }

        self.metadata = Option::Some(discovery_result.unwrap());
        
        Result::Ok(self)
    }

    fn client(&mut self) -> Result<AuthClient,Box<dyn std::error::Error>> {
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

    pub fn mk_login_url(&mut self, initial_target: &str) -> Result<(Url,String),Box<dyn std::error::Error>> {

        let client = self.client()?;
        
        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        
        let raw_state = CsrfToken::new_random().secret().clone() + "|" + initial_target;
        let state_token = CsrfToken::new(raw_state);
        // Generate the full authorization URL.
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                || state_token,
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            // Set the PKCE code challenge.
            //.set_pkce_challenge(pkce_challenge)
            .url();
        
        Result::Ok((auth_url, nonce.secret().into()))
    }

    pub fn exchange_code(&mut self, code: &str, nonce: &str) -> Result<String,Box<dyn std::error::Error>> {
        // Now you can exchange it for an access token and ID token.
        let client = self.client()?;
        let token_response = match client
                .exchange_code(AuthorizationCode::new(code.into()))
                // Set the PKCE code verifier.
                // .set_pkce_verifier(pkce_verifier)
                .request(http_client) {
                    Ok(r) => r,
                    Err(e) => return Err(Box::from(e.compat()))
                };

        // Extract the ID token claims after verifying its authenticity and nonce.
        let id_token = match token_response
            .id_token()
            .unwrap()
            .claims(&client.id_token_verifier(), &Nonce::new(nonce.into())) {
                Ok(t) => t,
                Err(e) => return Err(Box::from(e.compat()))
            };

        // Verify the access token hash to ensure that the access token hasn't been substituted for
        // another user's.
        if let Some(expected_access_token_hash) = id_token.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &token_response.id_token().unwrap().signing_alg().unwrap()
            ).unwrap();
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(Box::from(String::from("Invalid access token")));
            }
        }

        // The authenticated user's identity is now available. See the IdTokenClaims struct for a
        // complete listing of the available claims.
        println!(
            "User {} with e-mail address {} has authenticated successfully",
            id_token.subject().as_str(),
            id_token.email().map(|email| email.as_str()).unwrap_or("<not provided>"),
        );
        
        Result::Ok(token_response.access_token().secret().into())
    }

    pub fn validate(&self, bearer_token: &str) -> Result<(),Box<dyn std::error::Error>> {
        // TODO
        Err(Box::from(String::from("not implemented")))
    }
}

pub struct UserContext {

}

impl<'a,'r> FromRequest<'a, 'r> for UserContext {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> Outcome<UserContext, Self::Error> { 
        let authm = request.guard::<State<AuthManager>>().unwrap();
        let token = match request.headers().get("Authorization").last() {
            Some(bearer_token) => {
                let mut it = bearer_token.split_ascii_whitespace();
                let bearer_prefix = it.next().unwrap_or("");
                let token = it.next().unwrap_or("");
                
                if !String::from(bearer_prefix).eq_ignore_ascii_case("Bearer") {
                    return unauthorized_outcome();
                }

                match authm.validate(token) {
                    Ok(t) => t,
                    Err(e) => return unauthorized_outcome()
                }
            },
            None => return Outcome::Failure((rocket::http::Status::Unauthorized,())),
        };

        // FIXME: need to inspect claims of validated token
        Outcome::Success(UserContext{})
    }

}

fn unauthorized_outcome() ->  Outcome<UserContext, ()>{
    Outcome::Failure((rocket::http::Status::Unauthorized,()))
}
