#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use rocket::http::*;
use rocket::request::*;
use rocket::response::*;
use rocket::*;
use rocket_contrib::json::*;
use rocket_oauth2::hyper_sync_rustls_adapter::HyperSyncRustlsAdapter;
use rocket_oauth2::{Callback, OAuth2, OAuthConfig, Provider, TokenResponse};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct UserInfo {
    first_name: String,
    last_name: String,
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

#[get("/")]
fn index(ctx: State<Context>) -> Json<Overview> {
    Json(Overview {
        user_info: UserInfo {
            first_name: String::from("Mickey"),
            last_name: String::from("Mouse"),
            roles: vec![String::from("disney")],
        },
        site_refs: vec![ctx.all_sites[0].clone()],
    })
}

#[get("/<path..>")]
fn auth_fallback(path: PathBuf) -> Redirect {
    Redirect::to("do-login")
}

fn token_callback(
    request: &Request,
    token: TokenResponse,
) -> std::result::Result<Redirect, Box<::std::error::Error>> {
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
            Some(("/do-login", vec!["roles".to_string()])),
        ))
        .launch();
}
