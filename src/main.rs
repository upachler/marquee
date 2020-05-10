

#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

mod auth;

use rocket::{Request,Response,State};
use rocket::response::Responder;
use rocket::{response::Redirect, http::{Accept,MediaType, Status, Cookie, Cookies}};
use rocket::http::uri::{Uri};

#[get("/")]
fn index(ctx: auth::UserContext) -> String {
    let mut msg = String::from("Hello, user ");
    msg += "<your-name-here>";

    msg
}


fn split_to_tuple_2<'a>(s: &'a str, pattern_str: &str) -> Option<(&'a str,&'a str)> 
{
    let mut it = s.split(pattern_str);
    
    let s1 = if let Some(s) = it.next() {
        s
    } else {
        return None
    };
    let s2 = if let Some(s) = it.next() {
        s
    } else {
        return None
    };

    Some((s1,s2))
}

#[get("/token-exchange?<code>&<state>")]
fn token_exchange<'a>(code: String, state: String, mut cookies: Cookies, authm: State<auth::AuthManager>) -> Result<Redirect,Status>{
    let (query_nonce, redirect_uri) = if let Some(t) = split_to_tuple_2(state.as_str(), "|") {
        t
    } else {
        return Err(Status::BadRequest)
    };

    match cookies.get("nonce") {
        Some(nonce_cookie) => {
            match authm.exchange_code(code.as_str(), nonce_cookie.value()) {
                Ok(access_token) => {
                    cookies.remove(Cookie::named("nonce"));
                    cookies.add(Cookie::new("access_token", access_token));
                    Ok(Redirect::found(String::from(redirect_uri)))
                }
                Err(e) => Err(Status::BadRequest)
            }
        },
        None => Err(Status::BadRequest)
    }
}

fn accepts_html(accept: &Accept) -> bool {
    accept.media_types().find(|media_type| **media_type==MediaType::HTML).is_some()
}

#[catch(401)]
fn unauthorized<'a>(req: &Request) -> Response<'a>{
    let auth_manager = req.guard::<State<auth::AuthManager>>().unwrap();
    let redirect_to_uri = match req.accept() {
        Some(accept) => match accepts_html(accept) {
            true => {
                let initial_target = req.uri().to_string();
                match auth_manager.mk_login_url(initial_target.as_str()) {
                Ok(uri) => Some(uri),
                _ => None
                }
            },
            false => None
        }
        _ => None
    };

    match redirect_to_uri {
        Some((url,nonce)) => {
            req.cookies().add(Cookie::new("nonce", nonce));
            let redirect = Redirect::found(url.to_string());
            Response::build()
            .merge(redirect.respond_to(&req).unwrap())
            .finalize()
        }
        _ => {
            let mut b = Response::build();
            b.status(Status::Unauthorized);
            b.finalize()
        }
    }
}

fn main() {
    rocket::ignite()
    .mount("/", routes![index, token_exchange])
    .register(catchers![unauthorized])
    .manage(auth::AuthManager::default())
    .launch();   
}



