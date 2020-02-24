extern crate warp;

use warp::Filter;
use warp::http::StatusCode;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::Mutex;

mod database;
mod storage;
mod types;

use storage::Storage;

//use database;
//use storage;

pub type DB = Arc<Mutex<database::Database>>;

struct Storages {
    storageValidated: storage::StorageLocal,
    storagePending: storage::StorageLocal,
}
    
async fn api_by_user(usr: u32, validated: bool, db: DB, storages: Arc<Storages>) -> Result<impl warp::Reply, Infallible> {
 let mut res = db.lock().await.byUser(usr, validated, database::Page{limit: 100, offset: 0}).await;
 let stor = match validated {
     true => &storages.storageValidated,
     false => &storages.storagePending,
 };
 for entry in &mut res {
     entry.url = stor.urlFor(&entry.url);
 }
 return Ok(warp::reply::json(&res));
}

fn with_db(db: DB) -> impl Filter<Extract = (DB,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

fn with_storages(s: Arc<Storages>) -> impl Filter<Extract = (Arc<Storages>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || s.clone())
}

#[tokio::main]
async fn main() {
    let mut db_inner = database::Database::new(
        "postgres://valimage:valimage@localhost/valimage").await;
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
    let hello = warp::path!("hello" / String)
        .map(|name| format!("Hello, {}!", name));

    let api_byuser = warp::path!("api" / "byuser" / u32 / bool)
      .and(with_db(db))
      .and(with_storages(storages))
      .and_then(api_by_user);

    warp::serve(hello.or(api_byuser))
        .run(([127, 0, 0, 1], 3030))
        .await;
}