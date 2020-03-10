extern crate serde;

use std::time::SystemTime;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Configuration {
    pub database: String,
    pub secret: String,
    pub quota_count: u64,
    pub quota_size: u64,
    pub max_size: u64,
    pub accepted_types: Vec<String>,
    pub s3_bucket_live: String,
    pub s3_bucket_pending: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub store_uploader_address: bool,
}


#[derive(Deserialize, Serialize)]
pub struct Login {
    pub login: String,
    pub password: String,
}

#[derive(Deserialize, Serialize)]
pub struct ValidationResult {
    pub id: u32,
    pub response: u32,
}

#[derive(Deserialize, Serialize)]
pub struct ValitationBatch {
    pub batch: Vec<ValidationResult>,
}

#[derive(Deserialize, Serialize)]
pub struct Image {
    pub uid: u32,
    pub url: String,
}

#[derive(Deserialize, Serialize)]
pub struct ImageBatch {
    pub batch: Vec<Image>,
}

#[derive(Deserialize, Serialize)]
pub struct Entry {
    pub id: u32,
    pub uploader: u32,
    pub validated: i32,
    pub submitted_at: SystemTime,
    pub key: String,
}

#[derive(Deserialize, Serialize)]
pub struct Page {
    pub limit: u32,
    pub offset: u32,
}

#[derive(Deserialize, Serialize)]
pub struct ImagesQuery {
    pub validated: bool,
    pub declined: bool,
    pub pending: bool,
    pub key: String,
    pub user: u32,
    pub page: Page,
}