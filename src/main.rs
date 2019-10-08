#![feature(proc_macro_hygiene, decl_macro)]

extern crate serde;

//#[macro_use]
extern crate rocket;
extern crate base64;

extern crate jsonwebtoken as jwt;

mod oidc;
mod jwk;

use hyper::header::Location;
use rocket::outcome::IntoOutcome;
use rocket::http::*;
use rocket::request::*;
use rocket::response::Redirect;
use rocket::*;
use rocket_contrib::json::*;
use rocket_oauth2::hyper_sync_rustls_adapter::HyperSyncRustlsAdapter;
use rocket_oauth2::{OAuth2, OAuthConfig, Provider, TokenResponse};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::path::PathBuf;

const DO_LOGIN_PATH : &str = "/do-login";
//const PUBLIC_KEY : &str = "MIICnTCCAYUCBgFtkQo0PDANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdtYXJxdWVlMB4XDTE5MTAwMzA5NTIwOFoXDTI5MTAwMzA5NTM0OFowEjEQMA4GA1UEAwwHbWFycXVlZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKlntr6U7Gp6uXBqH+5j3SVVboRGiLBHZNnvv2ihSZjZ9Z5boUZU580lawAadFjP2P66nFjoysk45c7btsgz0Cu/80drbpBZIAkd0qNFHxBtjLgGiH95x+fZYLzPfxOfnIHi8HOssoNmK8/dTKjfHf7OjHlXyoaculTe3Sg37kymXux4MA/LgrMHOEMZ+NRgHOs8sdQDJuR2pkbJ+Fr1DEw4NO6C92dRlyJj2YauBzClYuwKA9lgOpQnJG4MeBojKqxkfYrKz2I2R9Fh9Ir0OpH6goBQM7mvGmri0zCz1UdlgFAONOs3uZEuCFMifZJV14VglN4Lzdd1REMtwnr/5NsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAeRFVxXTtvNlSl1NUPQeMLYsVm4AtlqZbxM8QY+9rBFt+sVN0ky3hY6IQoqiUnNzBT1M7Q4kRu3VTU6g7f3rkJO8/psxb0gDLuthK3iPoemJhnWyW+C6bqbQtuJNslOa1xkR08hntfGdBxSFpG3TkVHQ9XfUPopE6FEmHNuFgxhmlyd+TGrJ9EkaFioH4Pz+ZT1uN4Q92webqVhUUoajnB78yUOXYwEc11D1igIabUzfWETna6rGfEaWaAe+c9fBgNSAIM7wcTaiG+yODFrK8BHd5s4Qmmjgz98G7zIxlb+URwfGoIAZJdsqXKxZWcqm9lIgeJ7SHXM4lWtSAFfDjyw==";
const PUBLIC_KEY : &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqWe2vpTsanq5cGof7mPdJVVuhEaIsEdk2e+/aKFJmNn1nluhRlTnzSVrABp0WM/Y/rqcWOjKyTjlztu2yDPQK7/zR2tukFkgCR3So0UfEG2MuAaIf3nH59lgvM9/E5+cgeLwc6yyg2Yrz91MqN8d/s6MeVfKhpy6VN7dKDfuTKZe7HgwD8uCswc4Qxn41GAc6zyx1AMm5HamRsn4WvUMTDg07oL3Z1GXImPZhq4HMKVi7AoD2WA6lCckbgx4GiMqrGR9isrPYjZH0WH0ivQ6kfqCgFAzua8aauLTMLPVR2WAUA406ze5kS4IUyJ9klXXhWCU3gvN13VEQy3Cev/k2wIDAQAB";

#[derive(Serialize, Deserialize)]
struct UserInfo {
    first_name: String,
    last_name: String,
    email: String,
    roles: Vec<String>,
}

#[derive(Serialize, Clone)]
struct SiteReference {
    display_name: String,
    url: String,
    required_roles: Vec<String>,
}

#[derive(Serialize)]
struct Overview {
    user_info: UserInfo,
    site_refs: Vec<SiteReference>,
}

struct Context {
    all_sites: Vec<SiteReference>,
}

#[derive(Serialize, Deserialize)]
struct AccessToken {
    sub: String,
    exp: usize,
    roles: Vec<String>,
    email: Option<String>,
}

impl<'a, 'r> FromRequest<'a, 'r> for AccessToken {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> request::Outcome<AccessToken, ()> {
        request
            .cookies()
            .get_private("token")
            .and_then(|token| {
                let key = base64::decode(PUBLIC_KEY)
                .expect("malformed base64 key string");
                match jwt::decode::<AccessToken>(
                    &token.value(),
                    key.as_ref(),
                    &jwt::Validation::default(),
                ) {
                    Ok(token_data) => Some(token_data.claims),
                    Err(_) => None
                }
            })
            .into_outcome((Status::Unauthorized, ()))
    }
}

#[get("/")]
fn index(ctx: State<Context>, access_token: AccessToken) -> Json<Overview> {
    Json(Overview {
        user_info: UserInfo {
            first_name: String::from("Mickey"),
            last_name: String::from("Mouse"),
            roles: vec![String::from("disney")],
            email: access_token.email.unwrap_or(String::from("")),
        },
        site_refs: vec![ctx.all_sites[0].clone()],
    })
}

#[get("/<_path..>")]
fn auth_fallback(_path: PathBuf, access_token_opt: Option<AccessToken>) -> Redirect {
    Redirect::to(DO_LOGIN_PATH)
}

fn token_callback(
    request: &Request,
    token: TokenResponse,
) -> std::result::Result<Redirect, Box<dyn(::std::error::Error)>> {
    let mut cookies = request.guard::<Cookies>().expect("request cookies");

    // Set a private cookie with the access token
    cookies.add_private(
        Cookie::build("token", token.access_token)
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}

fn main() {
    let oauth_provider = Provider {
        auth_uri: Cow::from(
            "http://localhost:8080/auth/realms/marquee/protocol/openid-connect/auth",
        ),
        token_uri: Cow::from(
            "http://localhost:8080/auth/realms/marquee/protocol/openid-connect/token",
        ),
    };
    let oauth_config = OAuthConfig::new(
        oauth_provider,
        String::from("marquee"),
        String::from(""),
        String::from("/exchange-token"),
    );
    let context = Context {
        all_sites: vec![SiteReference {
            url: String::from("http://disney.com"),
            display_name: String::from("Disney"),
            required_roles: vec![String::from("disney")],
        }],
    };

    rocket::ignite()
        .manage(context)
        .mount("/", routes![index, auth_fallback])
        .attach(OAuth2::custom(
            HyperSyncRustlsAdapter,
            token_callback,
            oauth_config,
            "/exchange-token",
            Some((DO_LOGIN_PATH, vec!["roles".to_string()])),
        ))
        .attach(rocket::fairing::AdHoc::on_response("Authentication Redirector", |_req, res| {
            if res.status() == Status::Unauthorized {
                // FIXME: need to check if client is a browser (accepts HTML)
                res.merge(Response::build().status(Status::SeeOther).header(Location("foo".to_owned())).finalize())
            }
        }
        ))
        .launch();
}
