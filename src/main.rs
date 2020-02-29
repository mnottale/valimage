extern crate warp;
extern crate headers;
extern crate sha2;
extern crate hex;
extern crate serde;
extern crate rand;
extern crate bytes;
extern crate serde_yaml;

use std::time::SystemTime;
use std::fs;

use headers::{Cookie, HeaderMapExt};
use warp::Filter;
use warp::header;
use warp::Rejection;
use warp::reject;
use warp::reject::custom;
use warp::http::{HeaderMap, StatusCode, Response};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::Mutex;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

mod database;
mod storage;
mod types;
mod auth;

use storage::Storage;
use auth::{Authenticator, AuthenticatorDemo};
use serde::{Deserialize, Serialize};
use types::{Configuration, Page, ValidationResult};
//use database;
//use storage;

pub type DB = Arc<Mutex<database::Database>>;

struct Storages {
    storageValidated: storage::StorageLocal,
    storagePending: storage::StorageLocal,
}

#[derive(Deserialize, Serialize)]
struct AuthInfo {
    userId: u64,
    username: String,
    role: String,
}

async fn api_authinfo(ai: AuthInfo) -> Result<impl warp::Reply, Infallible> {
    return Ok(warp::reply::json(&ai));
}

async fn api_logout() -> Result<impl warp::Reply, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(warp::http::header::LOCATION, "/")
        .header(
            warp::http::header::SET_COOKIE,
            "BEARER=; SameSite=Strict; HttpOpnly",
            )
        .body(b"true".to_vec()).unwrap())
}

async fn api_login(login: types::Login, authenticator: Arc<AuthenticatorDemo>, secret: String) -> Result<impl warp::Reply, Infallible> {
    let res = authenticator.authenticate(&login.login, &login.password);
    match res {
        None => Ok(Response::builder().status(StatusCode::OK).body(b"false".to_vec()).unwrap()),
        Some(info) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(warp::http::header::LOCATION, "/")
            .header(
                warp::http::header::SET_COOKIE,
                format!("BEARER={}; SameSite=Strict; HttpOpnly", encode_auth(&secret, &info)),
            )
            .body(b"true".to_vec()).unwrap())
    }
}

async fn api_delete(imageId:u32, ai: AuthInfo, db: DB, storages: Arc<Storages>) -> Result<impl warp::Reply, Infallible> {
    if ai.userId == 0 {
        return Ok(warp::reply::json(&false));
    }
    let mut uidMatch = 0;
    if ai.role == "user" {
        uidMatch = ai.userId;
    }
    if let Some(entry) = db.lock().await.getOneIf(imageId, uidMatch).await {
        let stor = match entry.validated {
            0 => &storages.storageValidated,
            _ => &storages.storagePending,
        };
        stor.delete(entry.key);
        db.lock().await.deleteOne(imageId);
        return Ok(warp::reply::json(&true));
    }
    return Ok(warp::reply::json(&false));
}
async fn api_myimages(page: Page, ai: AuthInfo, db: DB, storages: Arc<Storages>) -> Result<impl warp::Reply, Infallible> {
    if ai.userId == 0 {
        let empty : Vec<i32> = Vec::new();
        return Ok(warp::reply::json(&empty));
    }
    let mut res = db.lock().await.allByUser(ai.userId as u32, page).await;
    for entry in &mut res {
        let stor = match entry.validated {
            0 => &storages.storageValidated,
            _ => &storages.storagePending,
        };
        entry.key = stor.urlFor(&entry.key);
    }
    return Ok(warp::reply::json(&res));
}

async fn api_images_to_validate(page: Page, ai: AuthInfo, db: DB, storages: Arc<Storages>) -> Result<impl warp::Reply, Infallible> {
    if ai.role != "reviewer" {
        let empty : Vec<i32> = Vec::new();
        return Ok(warp::reply::json(&empty));
    }
    let mut res = db.lock().await.pendingValidation(page).await;
    for entry in &mut res {
        let stor = match entry.validated {
            0 => &storages.storageValidated,
            _ => &storages.storagePending,
        };
        entry.key = stor.urlFor(&entry.key);
    }
    return Ok(warp::reply::json(&res));
}

async fn api_reply(vr: ValidationResult, ai: AuthInfo, db: DB, storages: Arc<Storages>) -> Result<impl warp::Reply, Infallible> {
    if ai.role != "reviewer" {
        return Ok(warp::reply::json(&false));
    }
    let key = db.lock().await.setResponse(vr.id, vr.response).await;
    if vr.response == 0 {
        // TODO proper move api storage dependent
        std::fs::rename(format!("store/pending/{}", &key), format!("store/live/{}", &key));
    }
    return Ok(warp::reply::json(&true));
}

async fn api_by_user(usr: u32, validated: bool, db: DB, storages: Arc<Storages>) -> Result<impl warp::Reply, Infallible> {
 let mut res = db.lock().await.byUser(usr, validated, Page{limit: 100, offset: 0}).await;
 let stor = match validated {
     true => &storages.storageValidated,
     false => &storages.storagePending,
 };
 for entry in &mut res {
     entry.url = stor.urlFor(&entry.url);
 }
 return Ok(warp::reply::json(&res));
}

fn make_key() -> String {
    let mut res = "img".to_string();
    let mut rng = thread_rng();
    let distr = rand::distributions::Uniform::new_inclusive('a' as i32, 'z' as i32);
    for i in 0..32 {
        res.push((rng.sample(distr) as u8) as char);
    }
    return res;
}
async fn api_upload(bytes: warp::hyper::body::Bytes, ai: AuthInfo, db: DB, storages: Arc<Storages>) -> Result<impl warp::Reply, Infallible> {
    if (ai.role != "user") {
        return Ok(Response::builder().status(StatusCode::FORBIDDEN).body(b"".to_vec()).unwrap());
    }
    let key = make_key();
    storages.storagePending.store(key.clone(), &bytes);
    db.lock().await.upload(ai.userId, &key).await;
    return Ok(Response::builder().status(StatusCode::OK).body(b"".to_vec()).unwrap());
}

fn with_db(db: DB) -> impl Filter<Extract = (DB,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

fn with_storages(s: Arc<Storages>) -> impl Filter<Extract = (Arc<Storages>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || s.clone())
}

fn with_authenticator(s: Arc<AuthenticatorDemo>) -> impl Filter<Extract = (Arc<AuthenticatorDemo>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || s.clone())
}

fn with_something(s: String) -> impl Filter<Extract = (String,), Error = Infallible> + Clone {
    warp::any().map(move || s.clone())
}

// uid/username/role/timestamp/signature
fn extract_auth(secret: &String, bearer: &String) -> AuthInfo {
    let default = AuthInfo { userId: 0, username: "".to_string(), role: "guest".to_string()};
    let comps : Vec<&str> = bearer.split('/').collect();
    if comps.len() != 5 {
        return default;
    }
    let to_sign = format!("{}@{}/{}/{}/{}", secret, comps[0], comps[1], comps[2], comps[3]);
    let mut hasher = Sha256::new();
    hasher.input(to_sign);
    let expect = hex::encode(hasher.result());
    if expect != comps[4] {
        return default;
    }
    let nowEpoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let bearerTS = u64::from_str_radix(comps[3], 10).unwrap_or(0);
    if nowEpoch - bearerTS > 3600 { // TODO: un-hardcode this
        return default;
    }
    return AuthInfo {
        userId: u64::from_str_radix(comps[0], 10).unwrap_or(0),
        username: comps[1].to_string(),
        role: comps[2].to_string(),
    }
}

fn encode_auth(secret: &String, ai: &AuthInfo) -> String {
    let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let to_sign = format!("{}@{}/{}/{}/{}", secret, ai.userId, ai.username, ai.role, ts);
    let mut hasher = Sha256::new();
    hasher.input(to_sign);
    let expect = hex::encode(hasher.result());
    return format!("{}/{}/{}/{}/{}", ai.userId, ai.username, ai.role, ts, expect);
}

fn with_auth(secret: &String) -> impl Filter<Extract = (AuthInfo,), Error = std::convert::Infallible> + Clone {
    let csec = secret.clone();
    header::headers_cloned().map(move |headers: HeaderMap| {
            let default = AuthInfo { userId: 0, username: "".to_string(), role: "guest".to_string()};
            let cookies = headers.typed_get::<Cookie>();
            match cookies {
                None => default,
                Some(c) => match c.get("BEARER") {
                    None => default,
                    Some(v) => extract_auth(&csec, &v.to_string())
                }
            }
    })
}
fn with_login_credentials() -> impl Filter<Extract = (types::Login,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

#[tokio::main]
async fn main() {
    let configContent = fs::read_to_string("config.yaml").unwrap();
    let config : Configuration = serde_yaml::from_str(&configContent).unwrap();
    let mut db_inner = database::Database::new(&config.database).await;
    let mut db = Arc::new(Mutex::new(db_inner));
    let storagePending = storage::StorageLocal{
        pathBase: "store/pending".to_string(),
        urlBase: "/pending".to_string()
    };
    let storageValidated = storage::StorageLocal{
        pathBase: "store/live".to_string(),
        urlBase: "/live".to_string()
    };
    let storages = Arc::new(Storages {
        storagePending: storagePending,
        storageValidated: storageValidated,
    });
    let authenticator = Arc::new(AuthenticatorDemo{});
    let hello = warp::path!("hello" / String)
        .map(|name| format!("Hello, {}!", name));

    let r_api_byuser = warp::path!("api" / "byuser" / u32 / bool)
      .and(with_db(db.clone()))
      .and(with_storages(storages.clone()))
      .and_then(api_by_user);

    let r_api_login = warp::path!("api" / "login")
        .and(with_login_credentials())
        .and(with_authenticator(authenticator))
        .and(with_something(config.secret.clone()))
        .and_then(api_login);
    let r_api_logout = warp::path!("api" / "logout")
        .and_then(api_logout);
    let r_api_authinfo = warp::path!("api" / "authinfo")
        .and(with_auth(&config.secret))
        .and_then(api_authinfo);
    let r_api_myimages = warp::path!("api" / "myimages")
        .and(warp::body::json())
        .and(with_auth(&config.secret))
        .and(with_db(db.clone()))
        .and(with_storages(storages.clone()))
        .and_then(api_myimages);
    let r_api_delete = warp::path!("api" / "imagedelete")
        .and(warp::body::json())
        .and(with_auth(&config.secret))
        .and(with_db(db.clone()))
        .and(with_storages(storages.clone()))
        .and_then(api_delete);
    let r_api_images_to_validate = warp::path!("api" / "imagespending")
        .and(warp::body::json())
        .and(with_auth(&config.secret))
        .and(with_db(db.clone()))
        .and(with_storages(storages.clone()))
        .and_then(api_images_to_validate);
    let r_api_reply = warp::path!("api" / "reply")
        .and(warp::body::json())
        .and(with_auth(&config.secret))
        .and(with_db(db.clone()))
        .and(with_storages(storages.clone()))
        .and_then(api_reply);
    let r_api_upload = warp::path!("api" / "upload")
        .and(warp::body::bytes())
        .and(with_auth(&config.secret))
        .and(with_db(db.clone()))
        .and(with_storages(storages.clone()))
        .and_then(api_upload);
    let r_imgs_pending = warp::path("pending")
        .and(warp::fs::dir("store/pending"));
    let r_imgs_live = warp::path("live")
        .and(warp::fs::dir("store/live"));
    let r_static = warp::path("static").and(warp::fs::dir("static"));
    let r_index = warp::path("index.html").and(warp::fs::file("./index.html"));
    warp::serve(hello
          .or(r_api_byuser)
          .or(r_api_login)
          .or(r_api_logout)
          .or(r_api_authinfo)
          .or(r_api_upload)
          .or(r_api_myimages)
          .or(r_api_images_to_validate)
          .or(r_api_reply)
          .or(r_index)
          .or(r_static)
          .or(r_imgs_pending)
          .or(r_imgs_live))
        .run(([127, 0, 0, 1], 3030))
        .await;
}