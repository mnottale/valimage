extern crate serde;

use serde::{Deserialize, Serialize};


#[derive(Deserialize, Serialize)]
pub struct ValidationResult {
    uid: u32,
    accept: bool,
    reason: u32,
}

#[derive(Deserialize, Serialize)]
pub struct ValitationBatch {
    batch: Vec<ValidationResult>,
}

#[derive(Deserialize, Serialize)]
pub struct Image {
    pub uid: u32,
    pub url: String,
}

#[derive(Deserialize, Serialize)]
pub struct ImageBatch {
    batch: Vec<Image>,
}
