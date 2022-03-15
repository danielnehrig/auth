pub mod auth {
    tonic::include_proto!("auth");
}

use std::sync::Arc;

use auth::auth_server::{Auth, AuthServer};
use futures::stream::StreamExt;
use mongodb::{bson::doc, options::ClientOptions};
use serde::{Deserialize, Serialize};
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

        let res = col
            .insert_one(
                Credentials {
                    username: req_in.username.clone(),
                    password: req_in.password.clone(),
                },
                None,
            )
            .await
            .unwrap();

        let reply = auth::Token {
            auth: format!("Hello {}!", req_in.username.clone()).into(),
        };

        Ok(Response::new(reply))
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
            .unwrap()
            .unwrap();

        let reply = auth::Token {
            auth: format!("{}", res.username.clone()).into(),
        };

        Ok(Response::new(reply))
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
