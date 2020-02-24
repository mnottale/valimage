use std::fs;

pub trait Storage {
    fn store(&self, key: String, data: &[u8]);
    fn delete(&self, key: String);
    fn urlFor(&self, key: &String) -> String;
}


pub struct StorageLocal {
    pub pathBase: String,
    pub urlBase: String,
}

impl Storage for StorageLocal {
    fn store(&self, key: String, data: &[u8]) {
        fs::write(format!("{}/{}", self.pathBase, key), data);
    }
    fn delete(&self, key: String) {
    }
    fn urlFor(&self, key: &String) -> String {
        return format!("{}/{}", self.urlBase, key);
    }
}