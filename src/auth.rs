use super::AuthInfo;

pub trait Authenticator {
    fn authenticate(&self, username: &String, password: &String) -> Option<AuthInfo>;
}

pub struct AuthenticatorDemo {
}

impl Authenticator for AuthenticatorDemo {
    fn authenticate(&self, username: &String, password: &String) -> Option<AuthInfo> {
        let mut role = String::new();
        let first = username.chars().next().unwrap();
        if first == 'u' {
            role = "user".to_string();
        }
        else if first == 'r' {
            role = "reviewer".to_string();
        }
        else if first == 'a' {
            role = "admin".to_string();
        }
        else {
            return None;
        }
        return Some(AuthInfo { 
            user_id: u64::from_str_radix(password, 10).unwrap_or(42),
            username: username.clone(),
            role: role
        });
    }
}