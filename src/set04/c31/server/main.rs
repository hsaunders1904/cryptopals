use cryptopals::server;

use axum::{routing::get, Router};

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9000));
    let app = Router::new().route("/test", get(server::handle_request));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
