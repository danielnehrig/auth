pub mod auth {
    tonic::include_proto!("auth");
}

use auth::auth_server::{Auth, AuthServer};
use tonic::transport::Server;

#[derive(Debug, Default)]
struct AuthService;

#[tonic::async_trait]
impl Auth for AuthService {
    fn register<'life0, 'async_trait>(
        &'life0 self,
        request: tonic::Request<auth::Credentials>,
    ) -> core::pin::Pin<
        Box<
            dyn core::future::Future<Output = Result<tonic::Response<auth::Token>, tonic::Status>>
                + core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        todo!()
    }

    fn login<'life0, 'async_trait>(
        &'life0 self,
        request: tonic::Request<auth::Credentials>,
    ) -> core::pin::Pin<
        Box<
            dyn core::future::Future<Output = Result<tonic::Response<auth::Token>, tonic::Status>>
                + core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
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
