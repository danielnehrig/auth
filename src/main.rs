pub mod auth {
    tonic::include_proto!("auth");
}

use auth::auth_server::{Auth, AuthServer};
use chrono::Utc;
use hmac::{Hmac, Mac};
use jwt::{claims::Claims, RegisteredClaims, SignWithKey, VerifyWithKey};
use mongodb::{
    bson::{self, doc},
    options::ClientOptions,
};
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::cell::RefCell;
use std::env;
use std::sync::Arc;
use tonic::{transport::Server, Response, Status};

#[derive(Debug)]
struct AuthService {
    client: Arc<mongodb::Client>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Credentials {
    #[serde(rename = "_id")]
    id: bson::oid::ObjectId,
    username: String,
    password: String,
}
use lazy_static::lazy_static;

lazy_static! {
    static ref JWT_SIGN_KEY: &'static str = "someValue1232$214124(aa$asd";
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

        let result = col
            .find_one(doc! {"username": req_in.username.clone()}, None)
            .await
            .unwrap();

        match result {
            Some(_) => Err(Status::already_exists("user already registered")),
            None => {
                let password_hash = Scrypt
                    .hash_password(req_in.password.as_bytes(), &salt)
                    .unwrap()
                    .to_string();

                let res = col
                    .insert_one(
                        Credentials {
                            username: req_in.username.clone(),
                            password: password_hash.clone(),
                            id: bson::oid::ObjectId::new(),
                        },
                        None,
                    )
                    .await
                    .unwrap();

                let key: Hmac<Sha256> = Hmac::new_from_slice(JWT_SIGN_KEY.as_bytes()).unwrap();
                let reg = RegisteredClaims::default();
                let mut claims = Claims::new(reg);
                let now = Utc::now();
                let exp = now.clone() + chrono::Duration::days(2);
                let claim_exp = exp.timestamp() as u64;
                let id_parse = res.inserted_id.as_object_id().unwrap().to_string();
                claims.registered.subject = Some(id_parse.clone());
                claims
                    .private
                    .insert("name".into(), Value::String(req_in.username));
                claims.registered.expiration = Some(claim_exp);
                claims
                    .private
                    .insert("role".into(), Value::String("user".to_string()));
                claims.registered.issuer = Some("dnehrig.com".to_string());
                claims.registered.issued_at = Some(now.timestamp() as u64);

                let token_str = claims.sign_with_key(&key).unwrap();

                let reply = auth::Token {
                    auth: token_str.clone(),
                };

                return Ok(Response::new(reply));
            }
        }
    }

    async fn refresh(
        &self,
        request: tonic::Request<auth::Token>,
    ) -> Result<Response<auth::Token>, Status> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(JWT_SIGN_KEY.as_bytes()).unwrap();
        let token = request.into_inner().auth;
        let sign_res: Result<RefCell<Claims>, _> = token.clone().as_str().verify_with_key(&key);
        let res = match sign_res {
            Ok(claims) => {
                if claims.borrow().registered.expiration.unwrap()
                    > Utc::now().timestamp().try_into().unwrap()
                {
                    let key: Hmac<Sha256> = Hmac::new_from_slice(JWT_SIGN_KEY.as_bytes()).unwrap();
                    let now = Utc::now();
                    let exp = now.clone() + chrono::Duration::days(2);
                    let claim_exp = exp.timestamp() as u64;
                    claims.borrow_mut().registered.expiration = Some(claim_exp);
                    claims.borrow_mut().registered.issued_at = Some(now.timestamp() as u64);

                    let token_str = claims.sign_with_key(&key).unwrap();
                    let reply = auth::Token { auth: token_str };
                    return Ok(Response::new(reply));
                }

                return Err(Status::unauthenticated("token expired"));
            }
            Err(_) => Err(Status::unauthenticated("invalid token")),
        };
        res
    }

    async fn verify(
        &self,
        request: tonic::Request<auth::Token>,
    ) -> Result<Response<auth::Token>, Status> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(JWT_SIGN_KEY.as_bytes()).unwrap();
        let token = request.into_inner().auth;
        let sign_res: Result<Claims, _> = token.clone().as_str().verify_with_key(&key);
        let res = match sign_res {
            Ok(claims) => {
                if claims.registered.expiration.unwrap()
                    > Utc::now().timestamp().try_into().unwrap()
                {
                    let reply = auth::Token {
                        auth: token.clone(),
                    };

                    return Ok(Response::new(reply));
                }

                return Err(Status::unauthenticated("token expired"));
            }
            Err(_) => Err(Status::unauthenticated("invalid token")),
        };
        res
    }

    async fn guest(&self, _: tonic::Request<()>) -> Result<Response<auth::Token>, Status> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(JWT_SIGN_KEY.as_bytes()).unwrap();
        let reg_claims = RegisteredClaims::default();
        let mut claims = Claims::new(reg_claims);
        let now = Utc::now();
        let exp = now.clone() + chrono::Duration::days(2);
        let claim_exp = exp.timestamp() as u64;
        claims.registered.subject = Some("GUEST".to_string());
        claims
            .private
            .insert("name".into(), Value::String("GUEST".to_string()));
        claims.registered.expiration = Some(claim_exp);
        claims
            .private
            .insert("role".into(), Value::String("GUEST".to_string()));
        claims.registered.issuer = Some("dnehrig.com".to_string());
        claims.registered.issued_at = Some(now.timestamp() as u64);

        let token_str = claims.sign_with_key(&key).unwrap();
        let reply = auth::Token {
            auth: token_str.clone(),
        };

        return Ok(Response::new(reply));
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
                let key: Hmac<Sha256> = Hmac::new_from_slice(JWT_SIGN_KEY.as_bytes()).unwrap();
                let reg_claims = RegisteredClaims::default();
                let mut claims = Claims::new(reg_claims);
                let now = Utc::now();
                let exp = now.clone() + chrono::Duration::days(2);
                let claim_exp = exp.timestamp() as u64;
                let id_parse = creds.id.to_string();
                claims.registered.subject = Some(id_parse.clone());
                claims
                    .private
                    .insert("name".into(), Value::String(req_in.username));
                claims.registered.expiration = Some(claim_exp);
                claims
                    .private
                    .insert("role".into(), Value::String("user".to_string()));
                claims.registered.issuer = Some("dnehrig.com".to_string());
                claims.registered.issued_at = Some(now.timestamp() as u64);

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
