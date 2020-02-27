extern crate tokio_postgres;
use tokio_postgres::{Client, NoTls, Error};

use std::time::{Duration, SystemTime};

use super::types::{Image, Entry, Page};
/*
CREATE TABLE images(
   id serial PRIMARY KEY,
   uploader BIGINT NOT NULL,
   response INT,
   validated_by BIGINT,
   submitted_at TIMESTAMP NOT NULL,
   validated_at TIMESTAMP,
   key VARCHAR(1024)
);
*/
pub struct Database {
    conn: Client,
}

impl Database {
    pub async fn new(url: &str) -> Database{
        let (client, conn) = tokio_postgres::connect(url, NoTls).await.unwrap();
        tokio::spawn(async move {
                if let Err(e) = conn.await {
                    eprintln!("connection error: {}", e);
                }
        });
        return Database {
            conn: client,
        };
    }
    // postgresql://user[:password]@host[:port][/database][?param1=val1[[&param2=val2]...]]
    pub async fn upload(&mut self, user: u64, key: &String) -> u64 {
        let biuser = user as i64;
        let rows = &self.conn.query("INSERT into images(uploader, key, submitted_at) VALUES($1, $2, NOW()) returning (id);",
            &[&biuser, key]).await.unwrap();
        let id: i32 = rows[0].get(0);
        return id as u64;
    }
    pub async fn byUser(&mut self, user: u32, validated: bool, page: Page) -> Vec<Image> {
        println!("Entering query");
        let biuser = user as i64;
        let bilimit = page.limit as i64;
        let bioffset = page.offset as i64;
        let rows = &self.conn.query("SELECT id, key FROM images WHERE uploader = $1 AND (response IS NOT NULL) = $2 ORDER BY submitted_at LIMIT $3 OFFSET $4",
            &[&biuser, &validated, &bilimit, &bioffset]).await.unwrap();
        println!("Bouining records...");
        let mut res = Vec::new();
        for row in rows {
            let iid: i32 = row.get(0);
            res.push(Image{uid: iid as u32, url: row.get(1)});
        }
        return res;
    }
    pub async fn allByUser(&mut self, user: u32, page: Page) -> Vec<Entry> {
        let biuser = user as i64;
        let bilimit = page.limit as i64;
        let bioffset = page.offset as i64;
        let mut res = Vec::new();
        let rows = &self.conn.query("SELECT id, response, submitted_at, key FROM images WHERE uploader = $1 ORDER BY submitted_at LIMIT $2 OFFSET $3",
            &[&biuser, &bilimit, &bioffset]).await.unwrap();
        for row in rows {
            let val : Option<i32> = row.get(1);
            let id : i32 = row.get(0);
            res.push(Entry{
                    id: id as u32,
                    uploader: user,
                    validated: val.unwrap_or(-1),
                    submitted_at: row.get(2),
                    key: row.get(3)
            });
        }
        return res;
    }
    pub async fn pendingValidation(&mut self, page: Page) -> Vec<Entry> {
        let bilimit = page.limit as i64;
        let bioffset = page.offset as i64;
        let mut res = Vec::new();
        let rows = &self.conn.query("SELECT id, response, submitted_at, key, uploader FROM images WHERE response is NULL ORDER BY submitted_at LIMIT $1 OFFSET $2",
            &[&bilimit, &bioffset]).await.unwrap();
        for row in rows {
            let val : Option<i32> = row.get(1);
            let id : i32 = row.get(0);
            let user : i64 = row.get(4);
            res.push(Entry{
                    id: id as u32,
                    uploader: user as u32,
                    validated: val.unwrap_or(-1),
                    submitted_at: row.get(2),
                    key: row.get(3)
            });
        }
        return res;
    }
    pub async fn setResponse(&mut self, id: u32, response: u32) -> String {
        let biid = id as i32;
        let iresp = response as i32;
        let rows = &self.conn.query("UPDATE images SET response=$1 WHERE id=$2 returning(key);",
            &[&iresp, &biid]).await.unwrap();
        return rows[0].get(0);
    }
}