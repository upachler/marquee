#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use rocket_contrib::json::*;
use serde::{Serialize,Deserialize};

#[derive(Serialize, Deserialize)]
struct UserInfo {
    first_name : String,
    last_name : String,
    roles : Vec<String>,
}

#[derive(Serialize, Clone)]
struct SiteReference {
    display_name : String,
    url : String,
    required_roles : Vec<String>,
}

#[derive(Serialize)]
struct Overview {
    user_info : UserInfo,
    site_refs : Vec<SiteReference>,
}


#[get("/")]
fn index<'a> () -> Json<Overview> {
    let all_sites : [SiteReference; 1] = [
        SiteReference {
            url: String::from("http://disney.com"),
            display_name : String::from("Disney"),
            required_roles : vec![String::from("disney")]
        }
    ];

    Json(Overview {
        user_info : UserInfo {
            first_name : String::from("Mickey"),
            last_name : String::from("Mouse"),
            roles : vec![String::from("disney")],
        },
        site_refs : vec![all_sites[0].clone()],
    })
}

fn main() {
    rocket::ignite().mount("/base", routes![index]).launch();
}
