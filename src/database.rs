extern crate tokio_postgres;
use tokio_postgres::{Client, NoTls, Error};

use std::time::{Duration, SystemTime};

use super::types::{Image};
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

pub struct Page {
    pub limit: u32,
    pub offset: u32,
}

pub struct Entry {
    id: u32,
    uploader: u32,
    validated: bool,
    submitted_at: SystemTime,
    key: String,
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
    pub async fn validationBatch(&mut self, page: Page) -> Vec<Entry> {
        let rows = &self.conn.query("SELECT id, uploader, validated, submitted_at, key FROM images where response IS NULL ORDER by submitted_at LIMIT $1 OFFSET $2",
            &[&page.limit, &page.offset]).await.unwrap();
        let mut res = Vec::new();
        for row in rows {
            res.push(Entry{
                    id: row.get(0),
                    uploader: row.get(1),
                    validated: row.get(2),
                    submitted_at: row.get(3),
                    key: row.get(4)
            });
        }
        return res;
    }
}