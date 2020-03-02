use std::fs;
use async_trait::async_trait;
use super::types::Configuration;

#[async_trait]
pub trait Storage: Sync + Send {
    fn configure(&mut self, config: &Configuration, isLive: bool) {}
    async fn get(&self, key: String) -> Vec<u8>;
    async fn store(&self, key: String, data: &[u8]);
    async fn delete(&self, key: String);
    async fn urlFor(&self, key: &String) -> String;
}


pub struct StorageLocal {
    pub pathBase: String,
    pub urlBase: String,
}

#[async_trait]
impl Storage for StorageLocal {
    async fn get(&self, key: String) -> Vec<u8> {
        return fs::read(format!("{}/{}", self.pathBase, key)).unwrap();
    }
    async fn store(&self, key: String, data: &[u8]) {
        fs::write(format!("{}/{}", self.pathBase, key), data);
    }
    async fn delete(&self, key: String) {
        fs::remove_file(format!("{}/{}", self.pathBase, key));
    }
    async fn urlFor(&self, key: &String) -> String {
        return format!("{}/{}", self.urlBase, key);
    }
}

extern crate s3;
use s3::credentials::Credentials;
use s3::bucket::Bucket;

pub struct StorageS3 {
    bucket: Option<Bucket>,
    isLive : bool,
}

impl StorageS3 {
    pub fn new(config: &Configuration, isLive: bool) -> StorageS3 {
        let mut ss3 = StorageS3{ bucket: None, isLive: false};
        ss3.configure(config, isLive);
        return ss3;
    }
}

#[async_trait]
impl Storage for StorageS3 {
    fn configure(&mut self, config: &Configuration, isLive: bool) {
        let bucketName = match isLive {
            true => &config.s3_bucket_live,
            false => &config.s3_bucket_pending,
        };
        let creds = Credentials::new(
            Some(config.s3_access_key.clone()),
            Some(config.s3_secret_key.clone()),
            None, None);
        self.bucket = Some(Bucket::new(bucketName, config.s3_region.parse().unwrap(), creds).unwrap());
        self.isLive = isLive;
    }
    // FIXME sync functions, sync functions everywhere!!!
    async fn get(&self, key: String) -> Vec<u8> {
        return self.bucket.as_ref().unwrap().get_object(&format!("/{}", key)).unwrap().0;
    }
    async fn store(&self, key: String, data: &[u8]) {
        self.bucket.as_ref().unwrap().put_object(&format!("/{}", key), data, "image/unknown").unwrap();
    }
    async fn delete(&self, key: String) {
        self.bucket.as_ref().unwrap().delete_object(&format!("/{}", key)).unwrap();
    }
    async fn urlFor(&self, key: &String) -> String {
        if self.isLive {
           return format!("http://s3.amazonaws.com/{}/{}", self.bucket.as_ref().unwrap().name(), key);
        } else {
            // FIXME: signed request, pending bucket might not be public
            return format!("http://s3.amazonaws.com/{}/{}", self.bucket.as_ref().unwrap().name(), key);
        }
    }
}
