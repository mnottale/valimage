extern crate serde;

use std::time::SystemTime;
use serde::{Deserialize, Serialize};

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