pub mod auth {
    tonic::include_proto!("auth");
}

use auth::auth_server::{Auth, AuthServer};
use tonic::{transport::Server, Response, Status};

#[derive(Debug, Default)]
struct AuthService;

#[tonic::async_trait]
impl Auth for AuthService {
    async fn register(
        &self,
        request: tonic::Request<auth::Credentials>,
    ) -> Result<Response<auth::Token>, Status> {
        println!("Got a request: {:?}", request);

        let reply = auth::Token {
            auth: format!("Hello {}!", request.into_inner().username).into(),
        };

        Ok(Response::new(reply))
    }

    async fn login(
        &self,
        _request: tonic::Request<auth::Credentials>,
    ) -> Result<Response<auth::Token>, Status> {
        todo!()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let greeter = AuthService::default();

    Server::builder()
        .add_service(AuthServer::new(greeter))
        .serve(addr)
        .await?;

    Ok(())
}
