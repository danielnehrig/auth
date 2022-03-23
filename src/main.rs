pub mod auth {
    tonic::include_proto!("auth");
}

use auth::auth_server::{Auth, AuthServer};
use chrono::Utc;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use mongodb::{bson::doc, options::ClientOptions};
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;
use tonic::{transport::Server, Response, Status};

#[derive(Debug)]
struct AuthService {
    client: Arc<mongodb::Client>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Credentials {
    username: String,
    password: String,
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn register(
        &self,
        request: tonic::Request<auth::Credentials>,
    ) -> Result<Response<auth::Token>, Status> {
        let db = self.client.default_database().unwrap();
        let col = db.collection::<Credentials>("users");

        let req_in = request.into_inner().clone();
        let salt = SaltString::generate(&mut OsRng);

        let password_hash = Scrypt
            .hash_password(req_in.password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // @TODO no duplicate usernames
        let _res = col
            .insert_one(
                Credentials {
                    username: req_in.username.clone(),
                    password: password_hash.clone(),
                },
                None,
            )
            .await
            .unwrap();

        let key: Hmac<Sha256> = Hmac::new_from_slice("234234234234".as_bytes()).unwrap();
        let mut claims = BTreeMap::new();
        let exp = Utc::now() + chrono::Duration::days(2);
        let claim_exp = exp.to_string().clone();
        claims.insert("name", req_in.username.as_str());
        claims.insert("expieres", claim_exp.as_str());
        claims.insert("role", "user");

        let token_str = claims.sign_with_key(&key).unwrap();

        let reply = auth::Token {
            auth: token_str.clone(),
        };

        Ok(Response::new(reply))
    }

    async fn refresh(
        &self,
        request: tonic::Request<auth::Token>,
    ) -> Result<Response<auth::Token>, Status> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(b"234234234234").unwrap();
        let token = request.into_inner().auth;
        let sign_res: Result<BTreeMap<String, String>, _> =
            token.clone().as_str().verify_with_key(&key);
        let res = match sign_res {
            Ok(data) => {
                let key: Hmac<Sha256> = Hmac::new_from_slice("234234234234".as_bytes()).unwrap();
                let mut claims = BTreeMap::new();
                let exp = Utc::now() + chrono::Duration::days(2);
                let claim_exp = exp.to_string().clone();
                claims.insert("name", data["name"].as_str());
                claims.insert("expieres", claim_exp.as_str());
                claims.insert("role", "user");

                let token_str = claims.sign_with_key(&key).unwrap();
                let reply = auth::Token { auth: token_str };
                Ok(Response::new(reply))
            }
            Err(_) => Err(Status::unauthenticated("invalid token")),
        };
        res
    }

    async fn verify(
        &self,
        request: tonic::Request<auth::Token>,
    ) -> Result<Response<auth::Token>, Status> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(b"234234234234").unwrap();
        let token = request.into_inner().auth;
        let sign_res: Result<BTreeMap<String, String>, _> =
            token.clone().as_str().verify_with_key(&key);
        let res = match sign_res {
            Ok(_) => {
                let reply = auth::Token {
                    auth: format!("{}", token.clone()).into(),
                };
                Ok(Response::new(reply))
            }
            Err(_) => Err(Status::unauthenticated("invalid token")),
        };
        res
    }

    async fn login(
        &self,
        request: tonic::Request<auth::Credentials>,
    ) -> Result<Response<auth::Token>, Status> {
        let db = self.client.default_database().unwrap();
        let col = db.collection::<Credentials>("users");

        let req_in = request.into_inner().clone();

        let res = col
            .find_one(doc! {"username": req_in.username.clone()}, None)
            .await
            .unwrap();

        if let Some(creds) = res {
            let parsed_hash = PasswordHash::new(creds.password.as_str()).unwrap();

            if Scrypt
                .verify_password(req_in.password.clone().as_bytes(), &parsed_hash)
                .is_ok()
            {
                let key: Hmac<Sha256> = Hmac::new_from_slice(creds.password.as_bytes()).unwrap();
                let mut claims = BTreeMap::new();
                claims.insert("name", creds.username.as_str());
                let exp = Utc::now() + chrono::Duration::days(2);
                let claim_exp = exp.to_string().clone();
                claims.insert("name", req_in.username.as_str());
                claims.insert("role", "user");
                claims.insert("expieres", claim_exp.as_str());

                let token_str = claims.sign_with_key(&key).unwrap();
                let reply = auth::Token {
                    auth: token_str.clone(),
                };

                return Ok(Response::new(reply));
            }

            return Err(Status::unauthenticated("invalid password"));
        }

        return Err(Status::unauthenticated("user not found"));
    }

    async fn health(&self, _request: tonic::Request<()>) -> Result<Response<()>, Status> {
        Ok(Response::new(()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mongo_port = env::var("MONGO_PORT").unwrap_or_else(|_| "27017".to_string());
    let mongo_host = env::var("MONGO_HOST").unwrap_or_else(|_| "localhost".to_string());
    let addr = "[::0]:3000".parse()?;

    let config = tonic_web::config().allow_all_origins();
    // Parse a connection string into an options struct.
    let mut client_options = ClientOptions::parse(format!(
        "mongodb://{}:{}",
        mongo_host.clone(),
        mongo_port.clone()
    ))
    .await?;

    // Manually set an option.
    client_options.default_database = Some("auth".to_string());
    client_options.app_name = Some("Authentication Service".to_string());

    // Get a handle to the deployment.
    let client = mongodb::Client::with_options(client_options)?;

    let greeter = AuthService {
        client: Arc::new(client),
    };

    println!("Running on {}", addr);
    Server::builder()
        .accept_http1(true)
        .add_service(config.enable(AuthServer::new(greeter)))
        .serve(addr)
        .await?;

    Ok(())
}
