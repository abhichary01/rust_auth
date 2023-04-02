use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use mysql::Opts;
use mysql::chrono::Duration;
use mysql::chrono::Utc;
use mysql::prelude::*;
use mysql::{from_row, Error, OptsBuilder};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use dotenv::dotenv;

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: Option<i32>,
    first_name: String,
    last_name: String,
    email: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserSignin {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    sub: String, // Subject
    exp: i64,    // Expiration time
}

fn establish_connection() -> Result<mysql::Pool, Error> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let opts = Opts::from_url(&database_url)?;
    mysql::Pool::new(opts)
}

fn generate_jwt(user_id: i32) -> String {
    let encoding_key = env::var("JWT_SECRET_KEY").unwrap_or_else(|_| "secret".into());
    let payload = Payload {
        sub: user_id.to_string(),
        exp: (Utc::now() + Duration::days(7)).timestamp(),
    };
    encode(
        &Header::default(),
        &payload,
        &EncodingKey::from_secret(encoding_key.as_bytes()),
    )
    .unwrap()
}

async fn register_user(
    user: web::Json<User>,
    pool: web::Data<mysql::Pool>,
) -> impl Responder {
    println!("cheeeck 01");
    let user = user.into_inner();
    println!("cheeeck 02");
    let hashed_password = hash(&user.password, DEFAULT_COST).unwrap();
    println!("cheeeck 03");
    let query = format!(
        "INSERT INTO users (first_name, last_name, email, username, password) VALUES ('{}', '{}', '{}', '{}', '{}')",
        user.first_name, user.last_name, user.email, user.username, hashed_password
    );
    println!("cheeeck 04");
    let result = pool
        .get_conn()
        .and_then(|mut conn| conn.query_drop(query));
    match result {
        Ok(_) => HttpResponse::Ok().body("User registered successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Error registering user"),
    }
}

async fn sign_in(
    user: web::Json<UserSignin>,
    pool: web::Data<mysql::Pool>,
) -> impl Responder {
    let user = user.into_inner();
    let query = format!(
        "SELECT id, password FROM users WHERE username = '{}'",
        user.username
    );
    let result = pool
        .get_conn()
        .and_then(|mut conn| conn.query_first::<(i32, String), _>(query));
    println!("cheeeck 04 {:?}",result);
    match result {
        Ok(Some((id, hashed_password))) => {
            if verify(&user.password, &hashed_password).unwrap_or(false) {
                let jwt = generate_jwt(id);
                HttpResponse::Ok().body(jwt)
            } else {
                HttpResponse::Unauthorized().body("Invalid username or password")
            }
        }
        Ok(None) => HttpResponse::Unauthorized().body("Invalid username or password"),
        Err(_) => HttpResponse::InternalServerError().body("Error signing in"),
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let pool = establish_connection().expect("Failed to create pool");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/register", web::post().to(register_user))
            .route("/signin", web::post().to(sign_in))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
