use std::fs;
use async_trait::async_trait;
use super::types::Configuration;

#[async_trait]
pub trait Storage: Sync + Send {
    fn configure(&mut self, config: &Configuration, isLive: bool) {}
    async fn get(&self, key: &String) -> Vec<u8>;
    async fn store(&self, key: &String, data: &[u8]);
    async fn delete(&self, key: &String);
    async fn urlFor(&self, key: &String) -> String;
}


pub struct StorageLocal {
    pub pathBase: String,
    pub urlBase: String,
}

#[async_trait]
impl Storage for StorageLocal {
    async fn get(&self, key: &String) -> Vec<u8> {
        return fs::read(format!("{}/{}", self.pathBase, key)).unwrap();
    }
    async fn store(&self, key: &String, data: &[u8]) {
        fs::write(format!("{}/{}", self.pathBase, key), data);
    }
    async fn delete(&self, key: &String) {
        fs::remove_file(format!("{}/{}", self.pathBase, key));
    }
    async fn urlFor(&self, key: &String) -> String {
        return format!("{}/{}", self.urlBase, key);
    }
}

extern crate rusoto_s3;
extern crate rusoto_credential;
extern crate rusoto_core;

use std::str::FromStr;
use std::io::Read;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;

use rusoto_s3::S3Client;
use rusoto_s3::S3;
//use tokio::io::util::async_read_ext::AsyncReadExt;

pub struct StorageS3 {
    client: Option<S3Client>,
    isLive: bool,
    bucket: String,
}

impl StorageS3 {
    pub fn new(config: &Configuration, isLive: bool) -> StorageS3 {
        let mut ss3 = StorageS3{ client: None, isLive: false, bucket: String::new()};
        ss3.configure(config, isLive);
        return ss3;
    }
}

#[async_trait]
impl Storage for StorageS3 {
    fn configure(&mut self, config: &Configuration, isLive: bool) {
        self.bucket = match isLive {
            true => &config.s3_bucket_live,
            false => &config.s3_bucket_pending,
        }.clone();
        let creds = rusoto_credential::StaticProvider::new_minimal(
            config.s3_access_key.clone(),
            config.s3_secret_key.clone()
            );
        self.client = Some(S3Client::new_with(
            rusoto_core::request::HttpClient::new().unwrap(),
            creds,
            rusoto_core::Region::from_str(&config.s3_region).unwrap()
            ));
        self.isLive = isLive;
    }

    async fn get(&self, key: &String) -> Vec<u8> {
        let resp = self.client.as_ref().unwrap().get_object(
            rusoto_s3::GetObjectRequest {
                bucket: self.bucket.clone(),
                key: format!("/{}", key),
                ..Default::default()
            }).await.unwrap();
        //let len = resp.content_length.unwrap();
        let mut astream = resp.body.unwrap().into_async_read();
        let mut buffer = Vec::new();
        astream.read_to_end(&mut buffer).await;
        return buffer;
    }
    async fn store(&self, key: &String, data: &[u8]) {
        //let haha : Result<bytes::Bytes, std::io::Error> = Ok(bytes::Bytes::from(data));
        //let mut sdata = futures::stream::iter(haha);
        let sdata = data.to_vec(); // err, does this copies??
        self.client.as_ref().unwrap().put_object(
            rusoto_s3::PutObjectRequest {
                key: format!("/{}", key),
                bucket: self.bucket.clone(),
                body: Some(rusoto_core::ByteStream::from(sdata)),
                ..Default::default()
            }).await.unwrap();
    }
    async fn delete(&self, key: &String) {
        self.client.as_ref().unwrap().delete_object(
            rusoto_s3::DeleteObjectRequest {
                key: format!("/{}", key),
                bucket: self.bucket.clone(),
                ..Default::default()
            }).await.unwrap();
    }
    async fn urlFor(&self, key: &String) -> String {
        if self.isLive {
           return format!("http://s3.amazonaws.com/{}/{}", self.bucket, key);
        } else {
            // FIXME: signed request, pending bucket might not be public
            return format!("http://s3.amazonaws.com/{}/{}", self.bucket, key);
        }
    }
}
