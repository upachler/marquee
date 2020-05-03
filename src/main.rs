

#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

mod auth;

use rocket::{Request,Response};
use rocket::response::Responder;
use rocket::{response::Redirect, http::{Accept,MediaType, Status}};

#[get("/")]
fn index(ctx: auth::UserContext) -> String {
    let mut msg = String::from("Hello, user ");
    msg += "<your-name-here>";

    msg
}

fn accepts_html(accept: &Accept) -> bool {
    accept.media_types().find(|media_type| **media_type==MediaType::HTML).is_some()
}

#[catch(401)]
fn unauthorized<'a>(req: &Request) -> Response<'a>{
    let redirect_to_uri = match req.accept() {
        Some(accept) => match accepts_html(accept) {
            true => match auth::mk_redirect_url() {
                Ok(uri) => Some(uri),
                _ => None
            },
            false => None
        }
        _ => None
    };

    match redirect_to_uri {
        Some(url) => {
            let redirect = Redirect::temporary(url.to_string());
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
    .mount("/", routes![index])
    .register(catchers![unauthorized])
    .launch();   
}



