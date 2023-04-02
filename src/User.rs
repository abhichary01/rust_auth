use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: Option<i32>,
    first_name: String,
    last_name: String,
    email: String,
    username: String,
    password: String,
}