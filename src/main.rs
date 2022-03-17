pub mod auth {
    tonic::include_proto!("auth");
}

use auth::auth_server::{Auth, AuthServer};
use futures::stream::StreamExt;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use mongodb::{bson::doc, options::ClientOptions};
use pbkdf2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
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
        println!("Got a request: {:?}", request);

        let db = self.client.default_database().unwrap();
        let col = db.collection::<Credentials>("users");

        let req_in = request.into_inner().clone();
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Pbkdf2
            .hash_password(req_in.password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // @TODO no duplicate usernames
        let res = col
            .insert_one(
                Credentials {
                    username: req_in.username.clone(),
                    password: password_hash.clone(),
                },
                None,
            )
            .await
            .unwrap();

        let key: Hmac<Sha256> = Hmac::new_from_slice(req_in.password.as_bytes()).unwrap();
        let mut claims = BTreeMap::new();
        claims.insert("name", req_in.username.as_str());
        claims.insert("role", "user");

        let token_str = claims.sign_with_key(&key).unwrap();

        let reply = auth::Token {
            auth: token_str.clone(),
        };

        Ok(Response::new(reply))
    }

    async fn verify(
        &self,
        request: tonic::Request<auth::Credentials>,
    ) -> Result<Response<auth::Token>, Status> {
        println!("Got a request: {:?}", request);

        let db = self.client.default_database().unwrap();
        let col = db.collection::<Credentials>("users");

        let req_in = request.into_inner().clone();

        let res = col
            .find_one(doc! {"username": req_in.username.clone()}, None)
            .await
            .unwrap()
            .unwrap();

        let parsed_hash = PasswordHash::new(res.password.as_str()).unwrap();
        if Pbkdf2
            .verify_password(req_in.password.clone().as_bytes(), &parsed_hash)
            .is_ok()
        {
            let reply = auth::Token {
                auth: format!("{}", res.username.clone()).into(),
            };

            return Ok(Response::new(reply));
        }

        return Err(Status::unauthenticated("guest"));
    }

    async fn login(
        &self,
        request: tonic::Request<auth::Credentials>,
    ) -> Result<Response<auth::Token>, Status> {
        println!("Got a request: {:?}", request);

        let db = self.client.default_database().unwrap();
        let col = db.collection::<Credentials>("users");

        let req_in = request.into_inner().clone();

        let res = col
            .find_one(doc! {"username": req_in.username.clone()}, None)
            .await
            .unwrap();

        if let Some(creds) = res {
            let parsed_hash = PasswordHash::new(creds.password.as_str()).unwrap();

            if Pbkdf2
                .verify_password(req_in.password.clone().as_bytes(), &parsed_hash)
                .is_ok()
            {
                let key: Hmac<Sha256> = Hmac::new_from_slice(creds.password.as_bytes()).unwrap();
                let mut claims = BTreeMap::new();
                claims.insert("name", creds.username.as_str());
                claims.insert("role", "guest");

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:50051".parse()?;

    let config = tonic_web::config().allow_all_origins();
    // Parse a connection string into an options struct.
    let mut client_options = ClientOptions::parse("mongodb://localhost:27017").await?;

    // Manually set an option.
    client_options.default_database = Some("auth".to_string());
    client_options.app_name = Some("My App".to_string());

    // Get a handle to the deployment.
    let client = mongodb::Client::with_options(client_options)?;

    let greeter = AuthService {
        client: Arc::new(client),
    };

    Server::builder()
        .accept_http1(true)
        .add_service(config.enable(AuthServer::new(greeter)))
        .serve(addr)
        .await?;

    println!("Running on {}", addr);
    Ok(())
}
